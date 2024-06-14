package net.vanderkast.lpes;

import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;

public record LpesPublicKeySpec(
        LpesPrivateKey privateKey,
        int[][] coefficients,
        int[][] errors
) implements KeySpec {

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LpesPublicKeySpec that = (LpesPublicKeySpec) o;
        return Objects.equals(privateKey, that.privateKey) && Arrays.equals(coefficients, that.coefficients) && Arrays.equals(errors, that.errors);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(privateKey);
        result = 31 * result + Arrays.hashCode(coefficients);
        result = 31 * result + Arrays.hashCode(errors);
        return result;
    }

    @Override
    public String toString() {
        return "LpesPublicKeySpec{" +
                "privateKey=" + privateKey +
                ", coefficients=" + Arrays.toString(coefficients) +
                ", errors=" + Arrays.toString(errors) +
                '}';
    }
}
