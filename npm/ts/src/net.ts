// IP address parsing with the exact acceptance of Rust's `core::net`
// `Ipv4Addr::from_str` and `Ipv6Addr::from_str`, which the Rust crate uses.
// Their rules differ from the WHATWG and `inet_pton` readings in the details
// that matter here: an IPv4 octet may not be zero-padded, an IPv6 group holds
// at most four hex digits, and an embedded IPv4 tail needs two groups of room.

/** Eight 16-bit groups. */
export type Ipv6 = readonly [number, number, number, number, number, number, number, number];

/** Four octets. */
export type Ipv4 = readonly [number, number, number, number];

/** A cursor over ASCII input, with Rust's `read_atomically` backtracking. */
class Cursor {
  constructor(
    readonly s: string,
    public at = 0,
  ) {}

  atomically<T>(read: () => T | undefined): T | undefined {
    const start = this.at;
    const value = read();
    if (value === undefined) this.at = start;
    return value;
  }

  char(c: string): true | undefined {
    if (this.s[this.at] === c) {
      this.at++;
      return true;
    }
    return undefined;
  }

  digit(radix: number): number | undefined {
    const code = this.s.charCodeAt(this.at);
    let d: number;
    if (code >= 0x30 && code <= 0x39) d = code - 0x30;
    else if (radix === 16 && code >= 0x61 && code <= 0x66) d = code - 0x61 + 10;
    else if (radix === 16 && code >= 0x41 && code <= 0x46) d = code - 0x41 + 10;
    else return undefined;
    if (d >= radix) return undefined;
    this.at++;
    return d;
  }

  /** `read_number`: at most `maxDigits` digits, within `max`, zero prefix optional. */
  number(radix: number, maxDigits: number, max: number, allowZeroPrefix: boolean): number | undefined {
    return this.atomically(() => {
      const leadingZero = this.s[this.at] === "0";
      let value = 0;
      let count = 0;
      for (let d = this.digit(radix); d !== undefined; d = this.digit(radix)) {
        value = value * radix + d;
        count++;
        if (value > max || count > maxDigits) return undefined;
      }
      if (count === 0) return undefined;
      if (!allowZeroPrefix && leadingZero && count > 1) return undefined;
      return value;
    });
  }

  ipv4(): Ipv4 | undefined {
    return this.atomically(() => {
      const octets: number[] = [];
      for (let i = 0; i < 4; i++) {
        if (i > 0 && this.char(".") === undefined) return undefined;
        const octet = this.number(10, 3, 0xff, false);
        if (octet === undefined) return undefined;
        octets.push(octet);
      }
      return octets as unknown as Ipv4;
    });
  }

  /** Read groups into `groups`; returns how many, and whether the last was IPv4. */
  groups(groups: number[], limit: number): [number, boolean] {
    for (let i = 0; i < limit; i++) {
      // A trailing embedded IPv4 address needs two groups of room.
      if (i < limit - 1) {
        const v4 = this.atomically(() => {
          if (i > 0 && this.char(":") === undefined) return undefined;
          return this.ipv4();
        });
        if (v4 !== undefined) {
          groups[i] = (v4[0] << 8) | v4[1];
          groups[i + 1] = (v4[2] << 8) | v4[3];
          return [i + 2, true];
        }
      }
      const group = this.atomically(() => {
        if (i > 0 && this.char(":") === undefined) return undefined;
        return this.number(16, 4, 0xffff, true);
      });
      if (group === undefined) return [i, false];
      groups[i] = group;
    }
    return [limit, false];
  }

  ipv6(): Ipv6 | undefined {
    return this.atomically(() => {
      const head = [0, 0, 0, 0, 0, 0, 0, 0];
      const [headSize, headIpv4] = this.groups(head, 8);
      if (headSize === 8) return head as unknown as Ipv6;
      if (headIpv4) return undefined;
      if (this.char(":") === undefined || this.char(":") === undefined) return undefined;
      const tail = [0, 0, 0, 0, 0, 0, 0];
      const [tailSize] = this.groups(tail, 8 - (headSize + 1));
      for (let i = 0; i < tailSize; i++) head[8 - tailSize + i] = tail[i]!;
      return head as unknown as Ipv6;
    });
  }
}

/** `Ipv4Addr::from_str`. */
export function parseIpv4(s: string): Ipv4 | undefined {
  const c = new Cursor(s);
  const addr = c.ipv4();
  return addr !== undefined && c.at === s.length ? addr : undefined;
}

/** `Ipv6Addr::from_str`. */
export function parseIpv6(s: string): Ipv6 | undefined {
  const c = new Cursor(s);
  const addr = c.ipv6();
  return addr !== undefined && c.at === s.length ? addr : undefined;
}

/** `Ipv6Addr::to_ipv4`: the mapped (`::ffff:a.b.c.d`) or compatible (`::a.b.c.d`) address. */
export function embeddedIpv4(addr: Ipv6): Ipv4 | undefined {
  const [a, b, c, d, e, f, g, h] = addr;
  if (a !== 0 || b !== 0 || c !== 0 || d !== 0 || e !== 0 || (f !== 0 && f !== 0xffff)) return undefined;
  return [g >> 8, g & 0xff, h >> 8, h & 0xff];
}

export function isIpv6Loopback(addr: Ipv6): boolean {
  return addr.every((g, i) => g === (i === 7 ? 1 : 0));
}

export function isIpv6Unspecified(addr: Ipv6): boolean {
  return addr.every((g) => g === 0);
}
