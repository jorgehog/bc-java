package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 *
 */
public class ASN1RealTest
        extends SimpleTest {
    public String getName() {
        return "ASN1Real";
    }

    public void checkNaN() {
        double out = decodeOrFail(Double.NaN, "42");
        isTrue("NaN failed", Double.isNaN(out));
    }

    public double decodeOrFail(double original, String expectedHex) {
        ASN1Real r = new ASN1Real(original);

        String hex = r.toHexString();

        isEquals(expectedHex + " != " + hex, hex, expectedHex);

        try {
            return r.getDoubleValue();
        } catch (Exception e) {
            fail(original + " failed (" + r.toHexString() + "): " + e);
            return 0.0;
        }
    }

    public void checkBitIdentical(double in, String expectedHex) {
        long inBits = Double.doubleToLongBits(in);

        double out = decodeOrFail(in, expectedHex);

        long outBits = Double.doubleToLongBits(out);

        isEquals(in + ": " + Long.toHexString(inBits) + " != " + Long.toHexString(outBits), inBits, outBits);
    }

    public void checkClose(double in, String expectedHex) {
        double out = decodeOrFail(in, expectedHex);

        double diff = Math.abs(in - out);

        isTrue(in + " !~= " + out, diff < 1E-15);
    }

    public void checkParser() throws IOException {
        ASN1Real value = new ASN1Real(10);

        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(value.getEncoded()));
        ASN1Primitive resultValue = stream.readObject();

        isEquals(value, resultValue);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(value);
        DERTaggedObject cValue = new DERTaggedObject(true, BERTags.APPLICATION, 2, new DERSequence(vector));

        ASN1InputStream cStream = new ASN1InputStream(new ByteArrayInputStream(cValue.getEncoded()));
        ASN1Primitive cResultValue = cStream.readObject();

        ASN1Real res = ((ASN1Real) ((ASN1Sequence) ((ASN1TaggedObject) cResultValue).getBaseObject()).getObjectAt(0));

        isEquals(res, value);
    }

    public void checkLowerBound() {
        // 2^(-1075)
        byte[] bytes = {(byte) 0x81, (byte) 0xfb, (byte) 0xcd, (byte) 0x01};
        ASN1Real r = new ASN1Real(bytes);
        isEquals(r.getDoubleValue(), 0.0d);
    }

    public void checkUpperBound() {
        // 2^1024
        byte[] bytes = {(byte) 0x81, (byte) 0x03, (byte) 0xcc, (byte) 0x01};
        try {
            ASN1Real r = new ASN1Real(bytes);
            fail("Upper bound breached");
        } catch (Exception e) {
        }
    }

    public void checkNonDERCases() {
        // 2*2^1
        byte[] bytes1 = {(byte) 0x80, (byte) 0x01, (byte) 0x02};
        double res1 = new ASN1Real(bytes1).getDoubleValue();
        isEquals(res1 + " != 4.0", res1, 4.0d);

        // 8*2^-1
        byte[] bytes2 = {(byte) 0x80, (byte) 0xff, (byte) 0x08};
        double res2 = new ASN1Real(bytes2).getDoubleValue();
        isEquals(res2 + " != 4.0", res2, 4.0d);

        // 1*2^2 alt
        byte[] bytes3 = {(byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
        double res3 = new ASN1Real(bytes3).getDoubleValue();
        isEquals(res3 + " != 4.0", res3, 4.0d);
    }

    @Override
    public void performTest() throws Exception {
        // Special case encoded with zero bits
        checkBitIdentical(0.0, "");

        // Special values
        checkBitIdentical(Double.POSITIVE_INFINITY, "40");
        checkBitIdentical(Double.NEGATIVE_INFINITY, "41");
        checkNaN(); // 42
        checkBitIdentical(-0.0, "43");

        // Misc. cases
        checkBitIdentical(1.0, "800001");
        checkBitIdentical(-1.0, "c00001");

        checkBitIdentical(2.0, "800101");
        checkBitIdentical(-2.0, "c00101");

        checkBitIdentical(0.5, "80ff01");
        checkBitIdentical(-0.5, "c0ff01");

        checkBitIdentical(0.75, "80fe03");
        checkBitIdentical(-0.75, "c0fe03");

        checkClose(10.0, "800105");
        checkClose(-10.0, "c00105");

        // 3602879701896397*2^(-55)
        checkClose(0.1, "80c90ccccccccccccd");
        checkClose(-0.1, "c0c90ccccccccccccd");

        // 2^(-1022)
        checkBitIdentical(Double.MIN_NORMAL, "81fc0201");
        checkBitIdentical(-Double.MIN_NORMAL, "c1fc0201");

        // (2^52 + (2^52-1))*2^971 = (2-1^(-52))*2^1023
        checkBitIdentical(Double.MAX_VALUE, "8103cb1fffffffffffff");
        checkBitIdentical(-Double.MAX_VALUE, "c103cb1fffffffffffff");

        // Subnormal cases

        // 2^(-1074)
        checkBitIdentical(Double.MIN_VALUE, "81fbce01");
        checkBitIdentical(-Double.MIN_VALUE, "c1fbce01");

        // just above and below the subnormal limits
        checkBitIdentical(0x0.0000000000003P-1022, "81fbce03");
        checkBitIdentical(0x0.fffffffffffffP-1022, "81fbce0fffffffffffff");

        checkLowerBound();
        checkUpperBound();

        // parsing
        checkParser();

        // Non DER case
        checkNonDERCases();

        // TODO: Check decimal case
        // TODO: Check base 10, 16 case
        // TODO: Check F case
    }

    public static void main(
            String[] args) {
        runTest(new ASN1RealTest());
    }
}
