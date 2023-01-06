import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Random;

public class User{
    private final String name;
    private Integer selfX;
    private final BigInteger alpha;
    private PrivateKey privateKey;
    private PublicKey selfPublicKey;
    private PublicKey otherPublicKey;
    private BigInteger SelfExponential;
    private BigInteger OtherExponential;
    private BigInteger sharedKey;

    public User(String name, BigInteger alpha){
        this.name = name;
        this.alpha = alpha;
    }

    public void generatePublicAndPrivateKey() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.selfPublicKey = keyPair.getPublic();
    }

    public BigInteger ComputeExponentialAndRandomNumber(){
        Random random = new Random();
        this.selfX = random.nextInt(20);
        return this.SelfExponential = this.alpha.pow(selfX);
    }

    public void SharedKeyCalculation(){
        sharedKey = OtherExponential.pow(selfX);
    }

    private byte[] ByteArrayConcatenation(byte[] arr1, byte[] arr2){
        byte[] result = new byte[arr1.length + arr2.length];
        ByteBuffer buffer = ByteBuffer.wrap(result);
        buffer.put(arr1);
        buffer.put(arr2);
        result = buffer.array();
        return result;
    }

    public Message CipherSignAndConcatenate(boolean isBob) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException{
        byte[] concat = ByteArrayConcatenation(SelfExponential.toByteArray(), OtherExponential.toByteArray());
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.privateKey);
        signature.update(concat);
        byte[] signBytes = signature.sign();
        AESImpl aes = new AESImpl();
        aes.setTheKey(sharedKey.toByteArray());
        byte[] cipheredSignature = aes.encrypt(signBytes);
        if(isBob)
            return new Message(cipheredSignature, SelfExponential);
        else
            return new Message(cipheredSignature, null);
    }

    public void DecryptionAndVerification(Message aliceAnswer) throws Exception{
        AESImpl aes = new AESImpl();
        aes.setTheKey(sharedKey.toByteArray());
        byte[] decryptedSignature = aes.decrypt(aliceAnswer.getCipheredSignature());
        byte[] concat = ByteArrayConcatenation(OtherExponential.toByteArray(), SelfExponential.toByteArray());
        Signature verifySignature = Signature.getInstance("SHA256withRSA");
        verifySignature.initVerify(this.otherPublicKey);
        verifySignature.update(concat);
        boolean isVerified = verifySignature.verify(decryptedSignature);
        if(!isVerified){
            throw new Exception("Verification failed.");
        }
    }

    public void setOtherExponential(BigInteger exp){
        this.OtherExponential = exp;
    }

    public void setOtherPublicKey(PublicKey pk){
        this.otherPublicKey = pk;
    }

    public PublicKey getSelfPublicKey(){
        return this.selfPublicKey;
    }

    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    public Integer getSelfX(){
        return selfX;
    }

    public BigInteger getSelfExponential(){
        return SelfExponential;
    }

    public BigInteger getSharedKey(){
        return sharedKey;
    }
}
