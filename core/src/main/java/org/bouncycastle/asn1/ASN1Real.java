package org.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;

import static org.bouncycastle.asn1.ASN1Integer.SIGN_EXT_SIGNED;
import static org.bouncycastle.asn1.ASN1Integer.SIGN_EXT_UNSIGNED;

/**
 * Class representing the ASN.1 REAL type.
 * <p>
 *     TODO
 * <p>
 * We should create an initial implementation under the same constraints. Others can extend on this if necessary.
 */
public class ASN1Real
        extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Real.class, BERTags.REAL) {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return createPrimitive(octetString.getOctets());
        }
    };

    private final byte[] bytes;

    public String toHexString() {
        return Hex.toHexString(bytes);
    }

    /**
     * Return an integer from the passed in object.
     *
     * @param obj an ASN1Real or an object that can be converted into one.
     * @return an ASN1Real instance.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Real getInstance(
            Object obj) {
        if (obj == null || obj instanceof ASN1Real) {
            return (ASN1Real) obj;
        }

        if (obj instanceof byte[]) {
            try {
                return (ASN1Real) TYPE.fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an Integer from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param explicit     true if the object is meant to be explicitly
     *                     tagged false otherwise.
     * @return an ASN1Real instance.
     * @throws IllegalArgumentException if the tagged object cannot
     *                                  be converted.
     */
    public static ASN1Real getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Real) TYPE.getContextInstance(taggedObject, explicit);
    }

    /**
     * Construct a REAL from the passed in double value.
     *
     * @param value the long representing the value desired.
     */
    public ASN1Real(double value) {
        if (value == Double.POSITIVE_INFINITY) {
            bytes = new byte[1];
            bytes[0] = 0x40;
        } else if (value == Double.NEGATIVE_INFINITY) {
            bytes = new byte[1];
            bytes[0] = 0x41;
        } else if (Double.isNaN(value)) {
            bytes = new byte[1];
            bytes[0] = 0x42;
        } else {
            long longBits = Double.doubleToLongBits(value);

            boolean isNegative = (longBits & 0x8000000000000000L) == 0x8000000000000000L;

            if (value == 0) {
                if (isNegative) {
                    bytes = new byte[1];
                    bytes[0] = 0x43;
                } else {
                    bytes = new byte[0];
                }
            } else {
                // Get last 12 bits, then drop the initial sign bit
                int IEEE754Exponent = ((int) (longBits >> 52)) & 0x7ff;

                // first 52 bits
                long IEEE754Mantissa = (longBits & 0x000fffffffffffffL);

                // subnormal means we should interpret the mantissa as 0.[b1][b2]... instead of 1.[b1][b2]...
                boolean subnormal = IEEE754Exponent == 0 && IEEE754Mantissa != 0;


                int exponent;
                long mantissa;
                // Normalize the exponent. 1023/1022 comes from the exponent shift in IEE754.
                // We also multiply by 2^52 to lift 52 bits of the mantissa above the comma since the mantissa in
                // IEEE754 is x.[b1][b2]..., whereas in X.690 it is represented as the integer x[b1][b2]... directly.
                if (subnormal) {
                    exponent = -1074; // -1022 - 52
                    mantissa = IEEE754Mantissa;
                } else {
                    exponent = IEEE754Exponent - 1075; // e - 1023 - 52
                    mantissa = IEEE754Mantissa | 0x0010000000000000L; // add leading 1
                }

                // There is no strict requirement in BER to care about ambiguous encodings, e.g. a = 5*2^1 or a = a*2^0.
                // However, in e.g. DER there is a requirement that the mantissa should be normalized such that "the
                // mantissa (unless it is 0) needs to be repeatedly shifted until the least significant bit is a 1."
                // (X.690 2008 Section 8.5.7.5 Note 1). Since the computation is straight forward we just always do it.
                int mantissaNumberOfTrailingZeros = Long.numberOfTrailingZeros(mantissa);

                exponent += mantissaNumberOfTrailingZeros;
                mantissa >>= mantissaNumberOfTrailingZeros;

                byte[] exponentBytes = BigInteger.valueOf(exponent).toByteArray();

                byte[] mantissaBytes = BigInteger.valueOf(mantissa).toByteArray();

                // binary encoding, base 2, no shifts. exponentBytes.length is guaranteed to be < 4.
                byte firstByte = (byte) ((exponentBytes.length - 1) | 0x80);

                if (isNegative) firstByte |= 0x40;

                byte[] firstArray = {firstByte}; // faster than concatenate + prepend

                bytes = Arrays.concatenate(firstArray, exponentBytes, mantissaBytes);
            }
        }
    }


    /**
     * Construct a REAL from the passed in byte array.
     *
     * @param bytes the byte array representing a ???.
     */
    public ASN1Real(byte[] bytes) {
        this(bytes, true);
    }

    ASN1Real(byte[] bytes, boolean clone) {
        this.bytes = clone ? Arrays.clone(bytes) : bytes;
    }

    public Double getDoubleValue() {
        if (bytes.length == 0) return 0.0d;

        byte first = bytes[0];

        if ((first & 0x80) == 0x80) {
            boolean isNegative = (first & 0x40) == 0x40;

            // For binary encoding we have three sources of exponents: 2^F*B^E,
            // where F is a scaling factor (0-3), B is the base (2, 8, or 16) and E is the exponent (signed).
            // This can be rewritten as 2^(F + L + E) := 2^exponent where L=log2(B) is 0, 3, or 4.
            // In DER F is zero, but we will not make that distinction at this point.
            int F = (first >> 2) & 0x03;

            int L;
            switch ((first >> 4) & 0x03) {
                case 0:
                    L = 0;
                    break;
                case 1:
                    L = 3;
                    break;
                case 2:
                    L = 4;
                    break;
                default:
                    throw new ASN1ParsingException("Base bits cannot be 11");
            }

            int E;
            int exponentLength;
            switch (first & 0x03) {
                case 0:
                    E = bytes[1] & SIGN_EXT_SIGNED;
                    exponentLength = 1;
                    break;
                case 1:
                    E = (bytes[1] & SIGN_EXT_SIGNED) << 8 | (bytes[2] & SIGN_EXT_UNSIGNED);
                    exponentLength = 2;
                    break;
                default:
                    // If we need more than two bytes to code the exponent we've blown the 12 bit budget already
                    throw new ArithmeticException("ASN.1 Real exponent above double exponent precision (11 bits)");
            }

            long exponent = L + E + F;

            long mantissa = ASN1Integer.longValue(bytes, 1 + exponentLength, SIGN_EXT_UNSIGNED);

            // Calculate the value the exponent would have in a denormalized form.
            long numTrailingMantissaZeros = Long.numberOfTrailingZeros(mantissa);
            long denormalizedExponent = exponent + 52 - numTrailingMantissaZeros;

            long longBits;

            if (denormalizedExponent == -1022) {
                longBits = mantissa >>> numTrailingMantissaZeros;
            } else if (denormalizedExponent < -1022) {
                // Gracefully return zero below the lower precision limit.
                longBits = 0L;
            } else {
                // Transforms the mantissa from 0000...1[b1][b2]... to .[b1][b2]...000
                // Since the leading 1 is implicit in IEEE754 an additional shift is performed to discard it.
                int mantissaShift = Long.numberOfLeadingZeros(mantissa) + 1;
                long IEEE754Mantissa = mantissa << mantissaShift;

                // To preserve the value, an opposite shift to the exponent is done.
                int exponentShift = (Long.SIZE - mantissaShift);
                long IEEE754Exponent = exponent + exponentShift + 1023;

                if (IEEE754Exponent > 0xffe) {
                    throw new ArithmeticException("ASN.1 Real exponent above double exponent precision (11 bits)");
                }

                longBits = (IEEE754Exponent << 52) | (IEEE754Mantissa >>> 12);
            }

            if (isNegative)
                longBits |= (0x8000000000000000L);

            return Double.longBitsToDouble(longBits);
        } else if ((first & 0xc0) == 0x00) {
            // ISO 6093 encoding is basically US_ASCII.
            String asciiString = new String(bytes, 1, bytes.length - 1, StandardCharsets.US_ASCII);

            // Replace the ISO 6093 decimal mark to that used by the Java parser.
            // DER puts many more restrictions on the string formatting, but these are only relevant for encoding.
            return Double.valueOf(asciiString.replace(',', '.'));
        } else {
            switch (first) {
                case 0x40:
                    return Double.POSITIVE_INFINITY;
                case 0x41:
                    return Double.NEGATIVE_INFINITY;
                case 0x42:
                    return Double.NaN;
                case 0x43:
                    return -0.0d;
                default:
                    throw new ASN1ParsingException("Unknown special real value " + first);
            }
        }
    }

    boolean encodeConstructed() {
        return false;
    }

    int encodedLength(boolean withTag) {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, bytes.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException {
        out.writeEncodingDL(withTag, BERTags.REAL, bytes);
    }

    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1Real)) {
            return false;
        }

        ASN1Real other = (ASN1Real) o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }

    public String toString() {
        return getDoubleValue().toString();
    }

    static ASN1Real createPrimitive(byte[] contents) {
        return new ASN1Real(contents, false);
    }
}
