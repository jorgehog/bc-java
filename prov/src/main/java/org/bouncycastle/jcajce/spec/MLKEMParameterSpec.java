package org.bouncycastle.jcajce.spec;

import org.bouncycastle.util.Strings;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

/**
 * AlgorithmSpec for ML-KEM
 */
public class MLKEMParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MLKEMParameterSpec ml_kem_512 = new MLKEMParameterSpec("ML-KEM-512");
    public static final MLKEMParameterSpec ml_kem_768 = new MLKEMParameterSpec("ML-KEM-768");
    public static final MLKEMParameterSpec ml_kem_1024 = new MLKEMParameterSpec("ML-KEM-1024");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("ML-KEM-512", MLKEMParameterSpec.ml_kem_512);
        parameters.put("ML-KEM-768", MLKEMParameterSpec.ml_kem_768);
        parameters.put("ML-KEM-1024", MLKEMParameterSpec.ml_kem_1024);

        parameters.put("kyber512", MLKEMParameterSpec.ml_kem_512);
        parameters.put("kyber768", MLKEMParameterSpec.ml_kem_768);
        parameters.put("kyber1024", MLKEMParameterSpec.ml_kem_1024);
    }

    private final String name;

    private MLKEMParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }
    
    public static MLKEMParameterSpec fromName(String name)
    {
        return (MLKEMParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
