import { connect } from 'cloudflare:sockets';

// 预编译常量 - V8内联缓存友好
const UUID = new Uint8Array([0x55,0xd9,0xec,0x38,0x1b,0x8a,0x45,0x4b,0x98,0x1a,0x6a,0xcf,0xe8,0xf5,0x6d,0x8c]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;
const ATYPE_IPV4 = 1;
const ATYPE_DOMAIN = 2;
const ATYPE_IPV6 = 3;

// 流控制常量
const MAX_BUFFER_SIZE = 64 * 1024; // 64KB 背压阈值
const HEADER_FRAME_SIZE = 8192; // 预分配首帧缓冲池大小

// 单例复用 - 避免重复实例化
const decoder = new TextDecoder();
const encoder = new TextEncoder();

// 错误对象预分配 - 避免动态创建
const PARSE_ERROR = Object.freeze({ host: '', end: 0, ok: false });

// 首帧缓冲池 - 减少动态分配
const headerBufferPool = new Uint8Array(HEADER_FRAME_SIZE + 2);
headerBufferPool[0] = 0;
headerBufferPool[1] = 0;

// 响应工厂 - 类型稳定（固定对象形状）
const makeResponse = (status, headers = null) => {
  const init = { status };
  if (headers) init.headers = headers;
  return new Response(null, init);
};

// Base64解码 - 返回值优化
const decodeBase64 = (str) => {
  try {
    const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const len = b.length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = b.charCodeAt(i);
    return { data: arr, ok: true };
  } catch {
    return { data: null, ok: false };
  }
};

// UUID验证 - 展开循环优化
const verifyUUID = (data) => {
  return data[1] === UUID[0] && data[2] === UUID[1] && data[3] === UUID[2] && data[4] === UUID[3] &&
         data[5] === UUID[4] && data[6] === UUID[5] && data[7] === UUID[6] && data[8] === UUID[7] &&
         data[9] === UUID[8] && data[10] === UUID[9] && data[11] === UUID[10] && data[12] === UUID[11] &&
         data[13] === UUID[12] && data[14] === UUID[13] && data[15] === UUID[14] && data[16] === UUID[15];
};

// 地址解析器 - 类型稳定（固定返回结构）
const parseAddress = (data, offset) => {
  const atype = data[offset + 3];
  const base = offset + 4;

  if (atype === ATYPE_DOMAIN) {
    const len = data[base];
    const end = base + 1 + len;
    if (end > data.length) return PARSE_ERROR;
    return { host: decoder.decode(data.subarray(base + 1, end)), end, ok: true };
  }

  if (atype === ATYPE_IPV4) {
    const end = base + 4;
    if (end > data.length) return PARSE_ERROR;
    return { host: `${data[base]}.${data[base+1]}.${data[base+2]}.${data[base+3]}`, end, ok: true };
  }

  if (atype === ATYPE_IPV6) {
    const end = base + 16;
    if (end > data.length) return PARSE_ERROR;
    const v = new DataView(data.buffer, data.byteOffset + base, 16);
    const host = `${v.getUint16(0).toString(16)}:${v.getUint16(2).toString(16)}:${v.getUint16(4).toString(16)}:${v.getUint16(6).toString(16)}:${v.getUint16(8).toString(16)}:${v.getUint16(10).toString(16)}:${v.getUint16(12).toString(16)}:${v.getUint16(14).toString(16)}`;
    return { host, end, ok: true };
  }

  return PARSE_ERROR;
};

// TCP连接器 - 移除try-catch到外部
const connectTCP = async (host, port, useFallback = false) => {
  const targetHost = useFallback ? PROXY_HOST : host;
  const targetPort = useFallback ? PROXY_PORT : port;
  const sock = connect({ hostname: targetHost, port: targetPort });
  await sock.opened;
  return sock;
};

// 连接管理类 - 避免闭包逃逸
class ConnectionHandler {
  constructor(server, tcp) {
    this.server = server;
    this.tcp = tcp;
    this.closed = false;
    this.bufferSize = 0;
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;

    // 分离错误处理 - 避免热路径污染
    this.safeClose(this.server);
    this.safeClose(this.tcp);
  }

  safeClose(resource) {
    try {
      if (resource && typeof resource.close === 'function') {
        resource.close();
      }
    } catch {}
  }

  // 背压检查
  canEnqueue() {
    return this.bufferSize < MAX_BUFFER_SIZE;
  }

  updateBuffer(delta) {
    this.bufferSize += delta;
  }
}

export default {
  async fetch(request) {
    // 快速路径检查
    const upgrade = request.headers.get('Upgrade');
    if (upgrade !== 'websocket') {
      return makeResponse(426, { Upgrade: 'websocket' });
    }

    const protocol = request.headers.get('Sec-WebSocket-Protocol');
    if (!protocol) return makeResponse(400);

    // 解码payload - 移除try-catch
    const decoded = decodeBase64(protocol);
    if (!decoded.ok) return makeResponse(400);
    const data = decoded.data;

    // 长度验证
    if (data.length < 18) return makeResponse(400);

    // UUID验证
    if (!verifyUUID(data)) return makeResponse(403);

    // 计算偏移
    const addrOffset = 18 + data[17];
    if (addrOffset + 4 > data.length) return makeResponse(400);

    // 解析端口
    const port = (data[addrOffset + 1] << 8) | data[addrOffset + 2];

    // 解析地址
    const addr = parseAddress(data, addrOffset);
    if (!addr.ok) return makeResponse(400);

    // 建立TCP连接 - 带回退
    let tcp;
    try {
      tcp = await connectTCP(addr.host, port, false);
    } catch {
      try {
        tcp = await connectTCP(addr.host, port, true);
      } catch {
        return makeResponse(502);
      }
    }

    // 创建WebSocket对
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    // 连接管理器
    const handler = new ConnectionHandler(server, tcp);
    const shutdown = () => handler.shutdown();

    // 上行流: WebSocket -> TCP（带背压控制）
    const uplink = new ReadableStream({
      start(controller) {
        // 初始数据
        if (data.length > addr.end) {
          const initialData = data.subarray(addr.end);
          controller.enqueue(initialData);
          handler.updateBuffer(initialData.length);
        }

        // 消息处理 - 类型单态化（只处理二进制）
        server.addEventListener('message', (event) => {
          if (handler.closed) return;

          const payload = event.data;
          let chunk;

          // 类型统一转换
          if (payload instanceof ArrayBuffer) {
            chunk = new Uint8Array(payload);
          } else if (typeof payload === 'string') {
            chunk = encoder.encode(payload);
          } else {
            return; // 忽略其他类型
          }

          // 背压控制
          if (!handler.canEnqueue()) {
            shutdown();
            return;
          }

          controller.enqueue(chunk);
          handler.updateBuffer(chunk.length);
        });

        server.addEventListener('close', () => {
          if (!handler.closed) {
            try { controller.close(); } catch {}
          }
        });

        server.addEventListener('error', shutdown);
      },

      // 实现pull策略 - 背压信号
      pull() {
        handler.updateBuffer(-4096); // 消费假设
      },

      cancel: shutdown
    });

    uplink.pipeTo(tcp.writable).catch(shutdown);

    // 下行流: TCP -> WebSocket（优化首帧分配）
    let isFirst = true;
    const downlink = new WritableStream({
      write(chunk) {
        if (handler.closed) return;

        if (isFirst) {
          isFirst = false;

          // 使用预分配缓冲池
          const chunkLen = chunk.length;
          if (chunkLen <= HEADER_FRAME_SIZE) {
            // 复用缓冲池
            headerBufferPool.set(chunk, 2);
            const frame = headerBufferPool.subarray(0, chunkLen + 2);
            server.send(frame);
          } else {
            // 超大首帧降级到动态分配
            const frame = new Uint8Array(chunkLen + 2);
            frame[0] = 0;
            frame[1] = 0;
            frame.set(chunk, 2);
            server.send(frame);
          }
        } else {
          server.send(chunk);
        }
      },
      close: shutdown,
      abort: shutdown
    });

    tcp.readable.pipeTo(downlink).catch(shutdown);

    return new Response(null, { status: 101, webSocket: client });
  }
};
