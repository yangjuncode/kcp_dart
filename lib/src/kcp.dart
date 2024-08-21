 import 'dart:math';
import 'dart:typed_data';

const IKCP_RTO_NDL = 30; // no delay min rto
 const IKCP_RTO_MIN = 100; // normal min rto
 const IKCP_RTO_DEF = 200;
 const IKCP_RTO_MAX = 60000;
 const IKCP_CMD_PUSH = 81; // cmd: push data
 const IKCP_CMD_ACK = 82; // cmd: ack
 const IKCP_CMD_WASK = 83; // cmd: window probe (ask)
 const IKCP_CMD_WINS = 84; // cmd: window size (tell)
 const IKCP_ASK_SEND = 1; // need to send IKCP_CMD_WASK
 const IKCP_ASK_TELL = 2; // need to send IKCP_CMD_WINS
 const IKCP_WND_SND = 32;
 const IKCP_WND_RCV = 32;
 const IKCP_MTU_DEF = 1400;
 const IKCP_ACK_FAST = 3;
 const IKCP_INTERVAL = 100;
 const IKCP_OVERHEAD = 24;
 const IKCP_DEADLINK = 20;
 const IKCP_THRESH_INIT = 2;
 const IKCP_THRESH_MIN = 2;
 const IKCP_PROBE_INIT = 7000; // 7 secs to probe window size
 const IKCP_PROBE_LIMIT = 120000; // up to 120 secs to probe window
 const IKCP_SN_OFFSET = 12;

var refTime = DateTime.now().millisecondsSinceEpoch;

int currentMs() {
  return DateTime.now().millisecondsSinceEpoch - refTime;
}

/* encode 8 bits unsigned int */
void ikcp_encode8u(Uint8List p, int c, [int offset = 0]) {
  p[offset] = c;
}

/* decode 8 bits unsigned int */
int ikcp_decode8u(Uint8List p, [int offset = 0]) {
  return p[offset];
}

/* encode 16 bits unsigned int (lsb) */
void ikcp_encode16u(Uint8List p, int w, [int offset = 0]) {
  p.buffer.asByteData().setUint16(offset, w, Endian.little);
}

/* decode 16 bits unsigned int (lsb) */
int ikcp_decode16u(Uint8List p, [int offset = 0]) {
  return p.buffer.asByteData().getUint16(offset, Endian.little);
}

/* encode 32 bits unsigned int (lsb) */
void ikcp_encode32u(Uint8List p, int l, [int offset = 0]) {
  p.buffer.asByteData().setUint32(offset, l, Endian.little);
}

/* decode 32 bits unsigned int (lsb) */
int ikcp_decode32u(Uint8List p, [int offset = 0]) {
  return p.buffer.asByteData().getUint32(offset, Endian.little);
}

int _ibound_(int lower, int middle, int upper) {
  return min(max(lower, middle), upper);
}

class Segment {
  // uint32
  // 会话ID
  int conv;
  // uint8
  // command 的缩写，代表此 segment 是什么类型
  // cmd 有4种，分别是
  // - 数据包 ( IKCP_CMD_PUSH )
  // - ACK 包 ( IKCP_CMD_ACK )
  // - 窗口探测包 ( IKCP_CMD_WASK )
  // - 窗口回应包 ( IKCP_CMD_WINS )
  int cmd;
  // uint8
  // fragment 的缩写
  // 代表数据分片的倒序序号，当数据大于 mss 时，需要将数据分片
  int frg;
  // uint16
  // window 的缩写
  int wnd;
  // uint32
  // timestamp 的缩写，当前 segment 发送的时间戳
  int ts;
  // sequence number 的缩写，代表 segment 的序列号
  int sn;
  // unacknowledged 的缩写，表示此编号之前的包都收到了
  int una;
  // Retransmision TimeOut，超时重传时间
  int rto;
  // segment 的发送次数，没发送一次加1，用于统计 segment 发送了几次
  int xmit;
  // 即 resend timestmap，指定的重传的时间戳
  int resendts;
  // 用于以数据驱动的快速重传机制
  int fastack;
  int acked;

  Uint8List? data;

  Segment({
    this.conv = 0,
    this.cmd = 0,
    this.frg = 0,
    this.wnd = 0,
    this.ts = 0,
    this.sn = 0,
    this.una = 0,
    this.rto = 0,
    this.xmit = 0,
    this.resendts = 0,
    this.fastack = 0,
    this.acked = 0,
    required this.data,
  });

  // encode a segment into buffer
  Uint8List encode(Uint8List ptr) {
    ikcp_encode32u(ptr, conv);
    ikcp_encode8u(ptr, cmd, 4);
    ikcp_encode8u(ptr, frg, 5);
    ikcp_encode16u(ptr, wnd, 6);
    ikcp_encode32u(ptr, ts, 8);
    ikcp_encode32u(ptr, sn, 12);
    ikcp_encode32u(ptr, una, 16);
    final len = data?.length ?? 0;
    ikcp_encode32u(ptr, len, 20);
    return Uint8List.sublistView(ptr, IKCP_OVERHEAD);
  }
}

class AckItem {
  int sn; // uint32
  int ts; // uint32

  AckItem({required this.sn, required this.ts});
}

typedef OutputCallback = void Function(Uint8List buf, int len, dynamic user);

class Kcp {
  int conv; // uint32
  int mtu; // uint32
  int mss; // uint32
  int state; // uint32
  // uint32
  int snd_una;
  int snd_nxt;
  int rcv_nxt;
  // uint32
  int ts_recent;
  int ts_lastack;
  int ssthresh;
  // int32
  int rx_rttvar;
  int rx_srtt;
  int rx_rto;
  int rx_minrto;
  // uint32
  int snd_wnd;
  int rcv_wnd;
  int rmt_wnd;
  // 拥塞窗口的大小
  int cwnd;
  int probe;
  // uint32
  int interval;
  int ts_flush;
  int xmit;

  int nodelay;
  int updated;

  int ts_probe;
  int probe_wait;

  int dead_link;
  int incr;

  List<Segment> snd_queue = [];
  List<Segment> rcv_queue = [];
  List<Segment> snd_buf = [];
  List<Segment> rcv_buf = [];

  List<AckItem> acklist = []; // ack 列表，收到的 ack 放在这里
  int ackcount = 0; // ack 的个数
  int ackblock = 0; // acklist 的大小，这个值 >= ackCount

  Uint8List? buffer;

  int fastresend; // int
  int nocwnd; // int
  int stream; // int

  dynamic user;
  OutputCallback? output;

  int reserved; // uint32

  Kcp({
    required this.conv,
    required this.user,
    this.mtu = IKCP_MTU_DEF,

    this.state = 0,

    this.snd_una = 0, // 发送出去未得到确认的包的序号
    this.snd_nxt = 0, // 下一个发出去的包的序号
    this.rcv_nxt = 0, // 待接收的下一个包的序号

    this.ts_recent = 0,
    this.ts_lastack = 0,
    this.ssthresh = IKCP_THRESH_INIT,

    this.rx_rttvar = 0,
    this.rx_srtt = 0,
    this.rx_rto = IKCP_RTO_DEF,
    this.rx_minrto = IKCP_RTO_MIN,

    this.snd_wnd = IKCP_WND_SND, // [发送窗口]的大小
    this.rcv_wnd = IKCP_WND_RCV, // [接收窗口]的大小
    this.rmt_wnd = IKCP_WND_RCV, // 远端的[接收窗口]的大小
    this.cwnd = 0,
    this.probe = 0,

    // this.current = 0,
    this.interval = IKCP_INTERVAL,
    this.ts_flush = IKCP_INTERVAL,
    this.xmit = 0,

    this.nodelay = 0,
    this.updated = 0,

    this.ts_probe = 0,
    this.probe_wait = 0,

    this.dead_link = IKCP_DEADLINK,
    this.incr = 0,

    this.fastresend = 0, // int
    this.nocwnd = 0, // int
    this.stream = 0, // int

    this.reserved = 0,
}): mss = mtu - IKCP_OVERHEAD,
        buffer = Uint8List(mtu);


  void _delSegment(Segment? seg) {
    if (seg?.data != null) {
      seg?.data = null;
    }
  }

  int setWndSize(int snd_wnd, int rcv_wnd) {
    if (snd_wnd > 0) {
      this.snd_wnd = snd_wnd;
    }
    if (rcv_wnd > 0) {
      this.rcv_wnd = rcv_wnd;
    }
    return 0;
  }

  int setMtu(int mtu) {
    if (mtu < 50 || mtu < IKCP_OVERHEAD) {
      return -1;
    }
    if (reserved >= this.mtu - IKCP_OVERHEAD || reserved < 0) {
      return -1;
    }

    late final Uint8List buffer;
    try {
      buffer = Uint8List(mtu);
    } catch (e) {
      return -2;
    }
    this.mtu = mtu;
    mss = this.mtu - IKCP_OVERHEAD - reserved;
    this.buffer = buffer;
    return 0;
  }

  // NoDelay options
  // fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
  // nodelay: 0:disable(default), 1:enable
  // interval: internal update timer interval in millisec, default is 100ms
  // resend: 0:disable fast resend(default), 1:enable fast resend
  // nc: 0:normal congestion control(default), 1:disable congestion control
  int setNoDelay(int nodelay, int interval, int resend, int nc) {
    if (nodelay >= 0) {
      this.nodelay = nodelay;
      if (nodelay != 0) {
        rx_minrto = IKCP_RTO_NDL;
      } else {
        rx_minrto = IKCP_RTO_MIN;
      }
    }
    if (interval >= 0) {
      if (interval > 5000) {
        interval = 5000;
      } else if (interval < 10) {
        interval = 10;
      }
      this.interval = interval;
    }
    if (resend >= 0) {
      fastresend = resend;
    }
    if (nc >= 0) {
      nocwnd = nc;
    }
    return 0;
  }

  void release() {
    snd_buf = [];
    rcv_buf = [];
    snd_queue = [];
    rcv_queue = [];
    buffer = null;
    acklist = [];
    ackcount = 0;
  }

  dynamic context() {
    return user;
  }

  (Uint8List buffer,int code) recv() {
    final peeksize = peekSize();
    if (peeksize < 0) {
      return (Uint8List(0), -1);
    }

    bool fast_recover = false;
    if (rcv_queue.length >= rcv_wnd) {
      fast_recover = true;
    }

    int n = 0;
    int count = 0;
      var builder = BytesBuilder(copy: false);
    for (final seg in rcv_queue) {
      builder.add(seg.data!);
      n += seg.data!.length;
      count++;
      _delSegment(seg);
      if (seg.frg == 0) {
        break;
      }
    }
    if (count > 0) {
      rcv_queue.removeRange(0, count);
    }

    // move available data from rcv_buf -> rcv_queue
    count = 0;
    for (final seg in rcv_buf) {
      if (seg.sn == rcv_nxt && rcv_queue.length + count < rcv_wnd) {
        rcv_nxt++;
        count++;
      } else {
        break;
      }
    }

    if (count > 0) {
      final segs = rcv_buf.sublist(0, count);
      rcv_queue.addAll(segs);
      rcv_buf.removeRange(0, count);
    }

    // fast recover
    if (rcv_queue.length < rcv_wnd && fast_recover) {
      probe |= IKCP_ASK_TELL;
    }
    return (builder.toBytes(), n);
  }

  // Input a packet into kcp state machine.
  //
  // 'regular' indicates it's a real data packet from remote, and it means it's not generated from ReedSolomon
  // codecs.
  //
  // 'ackNoDelay' will trigger immediate ACK, but surely it will not be efficient in bandwidth
  int input(Uint8List data, bool regular, bool ackNodelay) {
    final snd_una = this.snd_una;
    if (data.length < IKCP_OVERHEAD) {
      return -1;
    }

    int latest = 0; // uint32 , the latest ack packet
    int flag = 0; // int
    int inSegs = 0; // uint64 统计用
    bool windowSlides = false;

    while (true) {
      int ts = 0; // uint32
      int sn = 0; // uint32
      int length = 0; // uint32
      int una = 0; // uint32
      int conv = 0; // uint32
      int wnd = 0; // uint16
      int cmd = 0; // uint3
      int frg = 0; // uint8

      if (data.length < IKCP_OVERHEAD) {
        break;
      }

      conv = ikcp_decode32u(data);
      if (conv != this.conv) {
        return -1;
      }

      cmd = ikcp_decode8u(data, 4);
      frg = ikcp_decode8u(data, 5);
      wnd = ikcp_decode16u(data, 6);
      ts = ikcp_decode32u(data, 8);
      sn = ikcp_decode32u(data, 12);
      una = ikcp_decode32u(data, 16);
      length = ikcp_decode32u(data, 20);
      data = Uint8List.sublistView(data, IKCP_OVERHEAD);
      if (data.length < length) {
        return -2;
      }

      if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK && cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) {
        return -3;
      }

      // only trust window updates from regular packates. i.e: latest update
      if (regular) {
        rmt_wnd = wnd;
      }
      if (_parse_una(una) > 0) {
        windowSlides = true;
      }
      _shrink_buf();

      if (cmd == IKCP_CMD_ACK) {
        _parse_ack(sn);
        _parse_fastack(sn, ts);
        flag |= 1;
        latest = ts;
      } else if (cmd == IKCP_CMD_PUSH) {
        bool repeat = true;
        if (sn < this.rcv_nxt + this.rcv_wnd) {
          _ack_push(sn, ts);
          if (sn >= this.rcv_nxt) {
            final seg = Segment(
              conv: conv,
              cmd: cmd,
              frg: frg,
              wnd: wnd,
              ts: ts,
              sn: sn,
              una: una,
              data: Uint8List.sublistView(data, 0, length)
            );
            repeat = _parse_data(seg);
          }
        }
        if (regular && repeat) {
          // do nothing
          // 统计重复的包
        }
      } else if (cmd == IKCP_CMD_WASK) {
        // ready to send back IKCP_CMD_WINS in Ikcp_flush
        // tell remote my window size
        this.probe |= IKCP_ASK_TELL;
      } else if (cmd == IKCP_CMD_WINS) {
        // do nothing
      } else {
        return -3;
      }

      inSegs++;
      data = Uint8List.sublistView(data, length);
    }

    // update rtt with the latest ts
    // ignore the FEC packet
    if (flag != 0 && regular) {
      final current = currentMs();
      if (current >= latest) {
        _update_ack(current - latest);
      }
    }

    // cwnd update when packet arrived
    if (this.nocwnd == 0) {
      if (this.snd_una > snd_una) {
        if (this.cwnd < this.rmt_wnd) {
          final mss = this.mss;
          if (this.cwnd < this.ssthresh) {
            this.cwnd++;
            this.incr += mss;
          } else {
            if (this.incr < mss) {
              this.incr = mss;
            }
            this.incr += (mss * mss) ~/ this.incr + mss ~/ 16;
            if ((this.cwnd + 1) * mss <= this.incr) {
              if (mss > 0) {
                this.cwnd = (this.incr + mss - 1) ~/ mss;
              } else {
                this.cwnd = this.incr + mss - 1;
              }
            }
          }
          if (this.cwnd > this.rmt_wnd) {
            this.cwnd = this.rmt_wnd;
            this.incr = this.rmt_wnd * mss;
          }
        }
      }
    }

    if (windowSlides) {
      // if window has slided, flush
      flush(false);
    } else if (ackNodelay && this.acklist.length > 0) {
      // ack immediately
      flush(true);
    }
    return 0;
  }

  int _parse_una(int una) {
    int count = 0;
    for (final seg in this.snd_buf) {
      if (una > seg.sn) {
        _delSegment(seg);
        count++;
      } else {
        break;
      }
    }
    if (count > 0) {
      this.snd_buf.removeRange(0, count);
    }
    return count;
  }

  void _shrink_buf() {
    if (this.snd_buf.isNotEmpty) {
      final seg = this.snd_buf[0];
      this.snd_una = seg.sn;
    } else {
      this.snd_una = this.snd_nxt;
    }
  }

  void _parse_ack(int sn) {
    if (sn < this.snd_una || sn >= this.snd_nxt) {
      return;
    }

    for (final seg in this.snd_buf) {
      if (sn == seg.sn) {
        // mark and free space, but leave the segment here,
        // and wait until `una` to delete this, then we don't
        // have to shift the segments behind forward,
        // which is an expensive operation for large window
        seg.acked = 1;
        _delSegment(seg);
        break;
      }
      if (sn < seg.sn) {
        break;
      }
    }
  }

  void _parse_fastack(int sn, int ts) {
    if (sn < this.snd_una || sn >= this.snd_nxt) {
      return;
    }

    for (final seg in this.snd_buf) {
      if (sn < seg.sn) {
        break;
      } else if (sn != seg.sn && seg.ts <= ts) {
        seg.fastack++;
      }
    }
  }

  // returns true if data has repeated
  bool _parse_data(Segment newseg) {
    final sn = newseg.sn;
    if (sn >= this.rcv_nxt + this.rcv_wnd || sn < this.rcv_nxt) {
      return true;
    }

    int insert_idx = 0;
    bool repeat = false;
    if (this.rcv_buf.isNotEmpty) {
      final n = this.rcv_buf.length - 1;
      for (int i = n; i >= 0; i--) {
        final seg = this.rcv_buf[i];
        if (seg.sn == sn) {
          repeat = true;
          break;
        }
        if (sn > seg.sn) {
          insert_idx = i + 1;
          break;
        }
      }
    }

    if (!repeat) {
      // replicate the content if it's new
      final dataCopy = Uint8List.fromList(newseg.data!);
      newseg.data = dataCopy;
      this.rcv_buf.insert(insert_idx, newseg);
    }

    // move available data from rcv_buf -> rcv_queue
    int count = 0;
    for (final seg in this.rcv_buf) {
      if (seg.sn == this.rcv_nxt && this.rcv_queue.length + count < this.rcv_wnd) {
        this.rcv_nxt++;
        count++;
      } else {
        break;
      }
    }
    if (count > 0) {
      final segs = this.rcv_buf.sublist(0, count);
      this.rcv_queue.addAll(segs);
      this.rcv_buf.removeRange(0, count);
    }

    return repeat;
  }

  void _update_ack(int rtt) {
    // https://tools.ietf.org/html/rfc6298
    int rto = 0; // uint32
    if (this.rx_srtt == 0) {
      this.rx_srtt = rtt;
      this.rx_rttvar = rtt >> 1;
    } else {
      int delta = rtt - this.rx_srtt;
      this.rx_srtt += delta >> 3;
      if (delta < 0) {
        delta = -delta;
      }
      if (rtt < this.rx_srtt - this.rx_rttvar) {
        // if the new RTT sample is below the bottom of the range of
        // what an RTT measurement is expected to be.
        // give an 8x reduced weight versus its normal weighting
        this.rx_rttvar += (delta - this.rx_rttvar) >> 5;
      } else {
        this.rx_rttvar += (delta - this.rx_rttvar) >> 2;
      }
    }
    rto = this.rx_srtt + max(this.interval, this.rx_rttvar << 2);
    this.rx_rto = _ibound_(this.rx_minrto, rto, IKCP_RTO_MAX);
  }

  void _ack_push(int sn, int ts) {
    this.acklist.add(AckItem(sn: sn, ts: ts));
  }

  int send(Uint8List buffer) {
    int count = 0;
    if (buffer.isEmpty) {
      return -1;
    }

    // append to previous segment in streaming mode (if possible)
    if (this.stream != 0) {
      final n = this.snd_queue.length;
      if (n > 0) {
        final seg = this.snd_queue[n - 1];
        if (seg.data!.length < this.mss) {
          final capacity = this.mss - seg.data!.length;
          int extend = capacity;
          if (buffer.length < capacity) {
            extend = buffer.length;
          }

          // grow slice, the underlying cap is guaranteed to
          // be larger than kcp.mss
          seg.data!.addAll(Uint8List.sublistView(buffer, 0,extend));
          buffer = Uint8List.sublistView(buffer, extend);
        }
      }
    }

    if (buffer.length <= this.mss) {
      count = 1;
    } else {
      count = (buffer.length + this.mss - 1) ~/ this.mss;
    }

    if (count > 255) {
      return -2;
    }

    if (count == 0) {
      count = 1;
    }

    for (int i = 0; i < count; i++) {
      int size = 0;
      if (buffer.length > this.mss) {
        size = this.mss;
      } else {
        size = buffer.length;
      }
      final seg = Segment(data: Uint8List.sublistView(buffer, 0,size));

      if (this.stream == 0) {
        // message mode
        seg.frg = count - i - 1; // uint8
      } else {
        // stream mode
        seg.frg = 0;
      }
      this.snd_queue.add(seg);
      buffer = Uint8List.sublistView(buffer, size);
    }

    return 0;
  }

  void setOutput(OutputCallback output) {
    this.output = output;
  }

  // Update updates state (call it repeatedly, every 10ms-100ms), or you can ask
  // ikcp_check when to call it again (without ikcp_input/_send calling).
  // 'current' - current timestamp in millisec.
  void update() {
    int slap = 0; // int32

    final current = currentMs();
    if (this.updated == 0) {
      this.updated = 1;
      this.ts_flush = current;
    }

    slap = current - this.ts_flush;

    if (slap >= 10000 || slap < -10000) {
      this.ts_flush = current;
      slap = 0;
    }

    if (slap >= 0) {
      this.ts_flush += this.interval;
      if (current >= this.ts_flush) {
        this.ts_flush = current + this.interval;
      }
      flush(false);
    }
  }

  // Check determines when should you invoke ikcp_update:
  // returns when you should invoke ikcp_update in millisec, if there
  // is no ikcp_input/_send calling. you can call ikcp_update in that
  // time, instead of call update repeatly.
  // Important to reduce unnacessary ikcp_update invoking. use it to
  // schedule ikcp_update (eg. implementing an epoll-like mechanism,
  // or optimize ikcp_update when handling massive kcp connections)
  int check() {
    final current = currentMs();
    int ts_flush = this.ts_flush;
    int tm_flush = 0x7fffffff;
    int tm_packet = 0x7fffffff;
    int minimal = 0;

    if (this.updated == 0) {
      return 0;
    }

    if (current - ts_flush >= 10000 || current - ts_flush < -10000) {
      ts_flush = current;
    }

    if (current >= ts_flush) {
      return 0;
    }

    tm_flush = ts_flush - current;

    for (final seg in this.snd_buf) {
      final diff = seg.resendts - current;
      if (diff <= 0) {
        return 0;
      }
      if (diff < tm_packet) {
        tm_packet = diff;
      }
    }

    minimal = tm_packet;
    if (tm_packet >= tm_flush) {
      minimal = tm_flush;
    }
    if (minimal >= this.interval) {
      minimal = this.interval;
    }

    return minimal;
  }

  int _wnd_unused() {
    if (this.rcv_queue.length < this.rcv_wnd) {
      return this.rcv_wnd - this.rcv_queue.length;
    }
    return 0;
  }

  int flush(bool ackOnly) {
    final seg = Segment(data: Uint8List(0));
    seg.conv = conv;
    seg.cmd = IKCP_CMD_ACK;
    seg.wnd = _wnd_unused();
    seg.una = rcv_nxt;

    var ptr = Uint8List.sublistView(buffer!, reserved); // keep n bytes untouched

    // makeSpace makes room for writing
    void makeSpace(int space) {
      final size = buffer!.length - ptr.length;
      if (size + space > mtu) {
        if (output != null) {
          output!(buffer!, size, user);
        }
        ptr = Uint8List.sublistView(buffer!, reserved);
      }
    }

    // flush bytes in buffer if there is any
    void flushBuffer() {
      final size = buffer!.length - ptr.length;
      if (size > reserved) {
        if (output != null) {
          output!(buffer!, size, user);
        }
      }
    }

    // flush acknowledges
    for (var i = 0; i < acklist.length; i++) {
      final ack = acklist[i];
      makeSpace(IKCP_OVERHEAD);
      // filter jitters cased by bufferbloat
      if (ack.sn >= rcv_nxt || acklist.length - 1 == i) {
        seg.sn = ack.sn;
        seg.ts = ack.ts;
        ptr = seg.encode(ptr);
      }
    }
    acklist.clear();

    if (ackOnly) {
      // flash remain ack segments
      flushBuffer();
      return interval;
    }

    // probe window size (if remote window size equals zero)
    if (rmt_wnd == 0) {
      final current = currentMs();
      if (probe_wait == 0) {
        probe_wait = IKCP_PROBE_INIT;
        ts_probe = current + probe_wait;
      } else {
        if (current >= ts_probe) {
          if (probe_wait < IKCP_PROBE_INIT) {
            probe_wait = IKCP_PROBE_INIT;
          }
          probe_wait += probe_wait ~/ 2;
          if (probe_wait > IKCP_PROBE_LIMIT) {
            probe_wait = IKCP_PROBE_LIMIT;
          }
          ts_probe = current + probe_wait;
          probe |= IKCP_ASK_SEND;
        }
      }
    } else {
      ts_probe = 0;
      probe_wait = 0;
    }

    // flush window probing commands
    if ((probe & IKCP_ASK_SEND) != 0) {
      seg.cmd = IKCP_CMD_WASK;
      makeSpace(IKCP_OVERHEAD);
      ptr = seg.encode(ptr);
    }

    // flush window probing commands
    if ((probe & IKCP_ASK_TELL) != 0) {
      seg.cmd = IKCP_CMD_WINS;
      makeSpace(IKCP_OVERHEAD);
      ptr = seg.encode(ptr);
    }

    probe = 0;

    // calculate window size
    var cwnd = min(snd_wnd, rmt_wnd);
    if (nocwnd == 0) {
      cwnd = min(cwnd, this.cwnd);
    }

    // sliding window, controlled by snd_nxt && sna_una + cwnd
    var newSegsCount = 0;
    for (var k = 0; k < snd_queue.length; k++) {
      if (snd_nxt >= snd_una + cwnd) {
        break;
      }
      final newseg = snd_queue[k];
      newseg.conv = conv;
      newseg.cmd = IKCP_CMD_PUSH;
      newseg.sn = snd_nxt;
      snd_buf.add(newseg);
      snd_nxt++;
      newSegsCount++;
    }
    if (newSegsCount > 0) {
      snd_queue.removeRange(0, newSegsCount);
    }

    // calculate resent
    var resent = fastresend;
    if (fastresend <= 0) {
      resent = 0xFFFFFFFF;
    }

    // check for retransmissions
    final current = currentMs();
    var change = 0;
    var lostSegs = 0;
    var fastRetransSegs = 0;
    var earlyRetransSegs = 0;
    var minrto = interval;

    // const ref = this.snd_buf.slice(); // for bounds check elimination
    final ref = snd_buf;
    for (var k = 0; k < ref.length; k++) {
      final segment = ref[k];
      var needsend = false;
      if (segment.acked == 1) {
        continue;
      }
      if (segment.xmit == 0) {
        // initial transmit
        needsend = true;
        segment.rto = rx_rto;
        segment.resendts = current + segment.rto;
      } else if (segment.fastack >= resent) {
        // fast retransmit
        needsend = true;
        segment.fastack = 0;
        segment.rto = rx_rto;
        segment.resendts = current + segment.rto;
        change++;
        fastRetransSegs++;
      } else if (segment.fastack > 0 && newSegsCount == 0) {
        // early retransmit
        needsend = true;
        segment.fastack = 0;
        segment.rto = rx_rto;
        segment.resendts = current + segment.rto;
        change++;
        earlyRetransSegs++;
      } else if (current >= segment.resendts) {
        // RTO
        needsend = true;
        if (nodelay == 0) {
          segment.rto += rx_rto;
        } else {
          segment.rto += rx_rto ~/ 2;
        }
        segment.fastack = 0;
        segment.resendts = current + segment.rto;
        lostSegs++;
      }

      if (needsend) {
        final current = currentMs();
        segment.xmit++;
        segment.ts = current;
        segment.wnd = seg.wnd;
        segment.una = seg.una;

        final need = IKCP_OVERHEAD + segment.data!.length;
        makeSpace(need);
        ptr = segment.encode(ptr);
        ptr.setRange(ptr.length, ptr.length + segment.data!.length, segment.data!);
        ptr = Uint8List.sublistView(ptr, segment.data!.length);

        if (segment.xmit >= dead_link) {
          state = 0xFFFFFFFF;
        }
      }

      // get the nearest rto
      final rto = segment.resendts - current;
      if (rto > 0 && rto < minrto) {
        minrto = rto;
      }
    }

    // flush remain segments
    flushBuffer();

    // counter updates
    var sum = lostSegs;
    if (lostSegs > 0) {
      // stat
    }
    if (fastRetransSegs > 0) {
      sum += fastRetransSegs;
    }
    if (earlyRetransSegs > 0) {
      sum += earlyRetransSegs;
    }
    if (sum > 0) {
      // stat
    }

    // cwnd update
    if (nocwnd == 0) {
      // update ssthresh
      // rate halving, https://tools.ietf.org/html/rfc6937
      if (change > 0) {
        final inflight = snd_nxt - snd_una;
        ssthresh = inflight ~/ 2;
        if (ssthresh < IKCP_THRESH_MIN) {
          ssthresh = IKCP_THRESH_MIN;
        }
        cwnd = ssthresh + resent;
        incr = cwnd * mss;
      }

      // congestion control, https://tools.ietf.org/html/rfc5681
      if (lostSegs > 0) {
        ssthresh = cwnd ~/ 2;
        if (ssthresh < IKCP_THRESH_MIN) {
          ssthresh = IKCP_THRESH_MIN;
        }
        cwnd = 1;
        incr = mss;
      }

      if (cwnd < 1) {
        cwnd = 1;
        incr = mss;
      }
    }

    return minrto;
  }
  int peekSize() {
  if (rcv_queue.isEmpty) {
    return -1;
  }

  final seg = this.rcv_queue[0];
  if (seg.frg == 0) {
  return seg.data!.length;
  }

  if (this.rcv_queue.length < seg.frg + 1) {
  return -1;
  }

  var length = 0;
  for (final seg in this.rcv_queue) {
  length += seg.data!.length;
  if (seg.frg == 0) {
  break;
  }
  }
  return length;
}

 // WaitSnd gets how many packet is waiting to be sent
 int getWaitSnd() {
 return this.snd_buf.length + this.snd_queue.length;
 }

 bool setReserveBytes(int len) {
 if (len >= this.mtu - IKCP_OVERHEAD || len < 0) {
 return false;
 }
 this.reserved = len;
 this.mss = this.mtu - IKCP_OVERHEAD - len;
 return true;
 }
  }