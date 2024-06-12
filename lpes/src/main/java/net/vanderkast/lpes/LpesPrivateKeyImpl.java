package net.vanderkast.lpes;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.math.BigInteger;

@RequiredArgsConstructor
@Getter
public class LpesPrivateKeyImpl implements LpesPrivateKey {
    private final BigInteger N;
    private final BigInteger Q;
    private final BigInteger[] key;

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
