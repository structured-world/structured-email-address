// Length limits, counted in octets as the RFCs count them.

/** Maximum local-part length in octets (RFC 5321 §4.5.3.1.1). */
export const MAX_LOCAL_PART_LEN = 64;

/** Maximum addr-spec length in octets (RFC 5321 §4.5.3.1.3). */
export const MAX_ADDRESS_LEN = 254;

/** Maximum domain label length in octets (RFC 1035 §2.3.4). */
export const MAX_LABEL_LEN = 63;

/** UTF-8 length of a well-formed string, without encoding it. */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);
    if (unit < 0x80) n += 1;
    else if (unit < 0x800) n += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      // A surrogate pair is one four-byte code point.
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}
