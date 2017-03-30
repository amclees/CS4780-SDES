package sdes;

public class TripleSDES {
  
  public static byte[] Encrypt( byte[] rawkey1, byte[] rawkey2, byte[] plaintext ) {
    return SDES.Encrypt(rawkey1, SDES.Decrypt(rawkey2, SDES.Encrypt(rawkey1, plaintext)));
  }
  
  public static byte[] Decrypt( byte[] rawkey1, byte[] rawkey2, byte[] ciphertext ) {
    return SDES.Decrypt(rawkey1, SDES.Encrypt(rawkey2, SDES.Decrypt(rawkey1, ciphertext)));
  }
  
  public static byte[][] decryptBlocks(byte[] rawkey1, byte[] rawkey2, byte[][] ciphertext) {
    byte[][] plaintext = new byte[ciphertext.length][8];
    for(int i = 0; i < ciphertext.length; i++) {
      plaintext[i] = Decrypt(rawkey1, rawkey2, ciphertext[i]);
    }
    return plaintext;
  }
}
