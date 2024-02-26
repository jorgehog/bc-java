package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

import java.io.IOException;
import java.math.BigInteger;

public abstract class PublicKeyKeyEncryptionMethodGenerator
    extends PGPKeyEncryptionMethodGenerator
{
    public static final String SESSION_KEY_OBFUSCATION_PROPERTY = "org.bouncycastle.openpgp.session_key_obfuscation";
    public static final long WILDCARD = 0L;

    private static boolean getSessionKeyObfuscationDefault()
    {
        // by default we want this to be true.
        return !Properties.isOverrideSetTo(SESSION_KEY_OBFUSCATION_PROPERTY, false);
    }

    private PGPPublicKey pubKey;

    protected boolean sessionKeyObfuscation;
    protected boolean useWildcardKeyID;

    protected PublicKeyKeyEncryptionMethodGenerator(
        PGPPublicKey pubKey)
    {
        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
        case PGPPublicKey.ECDH:
        case PGPPublicKey.X25519:
        case PGPPublicKey.X448:
            break;
        case PGPPublicKey.RSA_SIGN:
            throw new IllegalArgumentException("Can't use an RSA_SIGN key for encryption.");
        case PGPPublicKey.DSA:
            throw new IllegalArgumentException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new IllegalArgumentException("Can't use ECDSA for encryption.");
        case PublicKeyAlgorithmTags.Ed448:
        case PublicKeyAlgorithmTags.Ed25519:
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            throw new IllegalArgumentException("Can't use EdDSA for encryption.");
        default:
            throw new IllegalArgumentException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        this.pubKey = pubKey;
        this.sessionKeyObfuscation = getSessionKeyObfuscationDefault();
    }

    /**
     * Controls whether to obfuscate the size of ECDH session keys using extra padding where necessary.
     * <p>
     * The default behaviour can be configured using the system property "", or else it will default to enabled.
     * </p>
     *
     * @return the current generator.
     */
    public PublicKeyKeyEncryptionMethodGenerator setSessionKeyObfuscation(boolean enabled)
    {
        this.sessionKeyObfuscation = enabled;

        return this;
    }

    /**
     * Controls whether the recipient key ID is hidden (replaced by a wildcard ID <pre>0</pre>).
     *
     * @param enabled boolean
     * @return this
     */
    public PublicKeyKeyEncryptionMethodGenerator setUseWildcardKeyID(boolean enabled)
    {
        this.useWildcardKeyID = enabled;

        return this;
    }

    public byte[][] processSessionInfo(
        byte[] encryptedSessionInfo)
        throws PGPException
    {
        byte[][] data;

        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            data = new byte[1][];

            data[0] = convertToEncodedMPI(encryptedSessionInfo);
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            byte[] b1 = new byte[encryptedSessionInfo.length / 2];
            byte[] b2 = new byte[encryptedSessionInfo.length / 2];

            System.arraycopy(encryptedSessionInfo, 0, b1, 0, b1.length);
            System.arraycopy(encryptedSessionInfo, b1.length, b2, 0, b2.length);

            data = new byte[2][];
            data[0] = convertToEncodedMPI(b1);
            data[1] = convertToEncodedMPI(b2);
            break;
        case PGPPublicKey.ECDH:
        case PGPPublicKey.X448:
        case PGPPublicKey.X25519:
            data = new byte[1][];

            data[0] = encryptedSessionInfo;
            break;
        default:
            throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
        }

        return data;
    }

    private byte[] convertToEncodedMPI(byte[] encryptedSessionInfo)
        throws PGPException
    {
        try
        {
            return new MPInteger(new BigInteger(1, encryptedSessionInfo)).getEncoded();
        }
        catch (IOException e)
        {
            throw new PGPException("Invalid MPI encoding: " + e.getMessage(), e);
        }
    }

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        long keyId;
        if (useWildcardKeyID)
        {
            keyId = WILDCARD;
        }
        else
        {
            keyId = pubKey.getKeyID();
        }
        return PublicKeyEncSessionPacket.createV3PKESKPacket(keyId, pubKey.getAlgorithm(), processSessionInfo(encryptSessionInfo(pubKey, sessionInfo)));
    }

    @Override
    public ContainedPacket generateV5(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        // TODO: Implement
        return null;
    }

    @Override
    public ContainedPacket generateV6(int encAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        // TODO: Implement
        return null;
    }

    abstract protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException;

    protected static byte[] getSessionInfo(byte[] ephPubEncoding, byte[] c)
        throws IOException
    {
        byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).getEncoded();

        byte[] rv = new byte[VB.length + 1 + c.length];
        System.arraycopy(VB, 0, rv, 0, VB.length);
        rv[VB.length] = (byte)c.length;
        System.arraycopy(c, 0, rv, VB.length + 1, c.length);
        return rv;
    }

    protected static byte[] getSessionInfo_25519or448(byte[] VB, int sysmmetricKeyAlgorithm, byte[] c)
    {
        byte[] rv = new byte[VB.length + 2 + c.length];
        System.arraycopy(VB, 0, rv, 0, VB.length);
        rv[VB.length] = (byte)(c.length + 1);
        rv[VB.length + 1] = (byte)sysmmetricKeyAlgorithm;
        System.arraycopy(c, 0, rv, VB.length + 2, c.length);
        return rv;
    }

    protected byte[] getHKDF(int hashAlgorithm, byte[] pubKeyPacket, byte[] secret, byte[] ephPubEncoding)
    {
        HKDF hkdf = new HKDF(hashAlgorithm);
        return hkdf.Extract(null, Arrays.concatenate(pubKeyPacket, secret, ephPubEncoding));
    }

    static class HKDF
    {
        private final HKDFBytesGenerator kdf;
        private final int hashLength;

        HKDF(int kdfId)
        {
            Digest hash;

            switch (kdfId)
            {
            case HashAlgorithmTags.SHA256:
                hash = new SHA256Digest();
                break;
            case HashAlgorithmTags.SHA384:
                hash = new SHA384Digest();
                break;
            case HashAlgorithmTags.SHA512:
                hash = new SHA512Digest();
                break;
            default:
                throw new IllegalArgumentException("invalid kdf id");
            }
            kdf = new HKDFBytesGenerator(hash);
            hashLength = hash.getDigestSize();
        }

        int getHashSize()
        {
            return hashLength;
        }

        /**
         * HKDF-Extract algorithm implementation.
         * <p>
         * This method extracts a pseudorandom key (PRK) using the HKDF-Extract function.
         *
         * @param salt optional salt value (a non-secret random value); if not provided,
         *             it is set to a byte array of HashLen zeros.
         * @param ikm  input keying material
         * @return a pseudorandom key (of HashLen bytes) generated using HMAC-Hash(salt, IKM)
         */
        public byte[] Extract(byte[] salt, byte[] ikm)
        {
            if (salt == null)
            {
                salt = new byte[hashLength];
            }

            return kdf.extractPRK(salt, ikm);
        }

        /**
         * HKDF-Expand algorithm implementation.
         * <p>
         * This method expands a pseudorandom key (PRK) into output keying material (OKM)
         * using the HKDF-Expand function.
         *
         * @param prk  a pseudorandom key of at least HashLen bytes
         *             (usually, the output from the extract step)
         * @param info optional context and application-specific information
         *             (can be a zero-length byte array)
         * @param L    length of output keying material in bytes
         *             (<= 65536*HashLen)
         * @return output keying material (of L bytes) generated using HKDF-Expand
         * @throws IllegalArgumentException if L is larger than 65536*HashLen
         */
        public byte[] Expand(byte[] prk, byte[] info, int L)
        {
            if (L > (1 << 16))
            {
                throw new IllegalArgumentException("Expand length cannot be larger than 2^16");
            }

            kdf.init(HKDFParameters.skipExtractParameters(prk, info));

            byte[] rv = new byte[L];

            kdf.generateBytes(rv, 0, rv.length);

            return rv;
        }
    }
}
