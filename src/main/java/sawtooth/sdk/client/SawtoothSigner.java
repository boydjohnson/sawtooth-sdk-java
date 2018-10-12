package sawtooth.sdk.client;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util.AssertFailException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;

/**
 * Class to produce valid Sawtooth signatures using secp256k1.
 */
public final class SawtoothSigner {

  /**
   * Constructor.
   */
  private SawtoothSigner() { };

  /**
   * The number of bytes in the signature.
   */
  public static final int NUM_SIGNATURE_BYTES = 64;

  /**
   * Half the number of bytes in the signature.
   */
  public static final int HALF_NUM_SIGNATURE_BYTES = 32;

  /**
   * Generate a ECKey private key from secure random number generator.
   *
   * @param random A random number generator.
   * @return The ECKey private key.
   */
  public static ECKey generatePrivateKey(final SecureRandom random) {
    return new ECKey(random);
  }

  /**
   * Return a public key for the given private key.
   *
   * @param privateKey The ECKey private key.
   * @return A hex representation of the Public Key bytes.
   */
  public static String getPublicKey(final ECKey privateKey) {
    return ECKey.fromPrivate(privateKey.getPrivKey(), true).getPublicKeyAsHex();
  }

  /**
   * Returns a bitcoin-style 64-byte compact signature.
   *
   * @param privateKey the private key with which to sign
   * @param data       the data to sign
   * @return String the signature
   * // @formatter:off
   * def sign(self, message, private_key):
   * try:
   * signature = private_key.secp256k1_private_key.ecdsa_sign(message)
   * signature = private_key.secp256k1_private_key \
   * .ecdsa_serialize_compact(signature)
   * <p>
   * return signature.hex()
   * // @formatter:on
   */
  public static String signHexSequence(final ECKey privateKey, final byte[] data) {

    return Utils.HEX.encode(generateCompactSig(privateKey, data)).toLowerCase();
  }

  /**
   * Returns a bitcoin-style 64-byte compact signature.
   *
   * @param privateKey the private key with which to sign
   * @param data       the data to sign
   * @return String the signature
   */
  public static String signASCII(final ECKey privateKey, final byte[] data) {

    return new String(generateCompactSig(privateKey, data), StandardCharsets.US_ASCII);
  }

  /**
   * Generate a signature from bytes, data.
   *
   * @param privateKey The private key to sign with.
   * @param data       The data to sign.
   * @return bytes of the signature.
   */
  public static byte[] generateCompactSig(final ECKey privateKey, final byte[] data) {
    Sha256Hash hash = Sha256Hash.of(data);
    ECKey.ECDSASignature sig = privateKey.sign(hash);

    byte[] csig = new byte[NUM_SIGNATURE_BYTES];

    System.arraycopy(Utils.bigIntegerToBytes(sig.r, HALF_NUM_SIGNATURE_BYTES), 0,
        csig, 0, HALF_NUM_SIGNATURE_BYTES);
    System.arraycopy(Utils.bigIntegerToBytes(sig.s, HALF_NUM_SIGNATURE_BYTES), 0,
        csig, HALF_NUM_SIGNATURE_BYTES, HALF_NUM_SIGNATURE_BYTES);
    return csig;
  }

  /**
   * Sign with a native secp256k1 shared library.
   *
   * @param privateKey The ECKey private key.
   * @param hashedData The data to sign.
   * @return the bytes of the signature.
   * @throws AssertFailException Assertions about the data to sign, and the private key fail.
   */
  public static byte[] signWithNativeSecp256k1(final ECKey privateKey,
                                               final Sha256Hash hashedData) throws AssertFailException {
    return NativeSecp256k1.sign(hashedData.getBytes(), privateKey.getPrivKeyBytes());
  }
}
