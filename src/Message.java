import java.math.BigInteger;

public class Message{
    private byte[] cipheredSignature; //alice to bob has only this
    private BigInteger alphaY;

    public Message(byte[] cipheredSignature, BigInteger alphaY){
        this.cipheredSignature = cipheredSignature;
        this.alphaY = alphaY;
    }

    public byte[] getCipheredSignature(){
        return cipheredSignature;
    }

    public BigInteger getAlphaY(){
        return alphaY;
    }
}
