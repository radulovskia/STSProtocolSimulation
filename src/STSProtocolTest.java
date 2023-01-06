import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

public class STSProtocolTest{
    public static void main(String[] args) throws Exception{
        System.out.println("SIMULATION STARTED AT " + LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS));
        BigInteger alpha = new BigInteger("123456");
        User Alice = new User("Alice", alpha);
        User Bob = new User("Bob", alpha);

        Alice.generatePublicAndPrivateKey();
        System.out.println("ALICE PRIVATE AND PUBLIC KEYS ARE: " + Alice.getPrivateKey() + " \nAND\n " + Alice.getSelfPublicKey());
        Bob.generatePublicAndPrivateKey();
        System.out.println("BOB PRIVATE AND PUBLIC KEYS ARE: " + Bob.getPrivateKey() + " \nAND\n " + Bob.getSelfPublicKey() + "\n");

        BigInteger alphaX = Alice.ComputeExponentialAndRandomNumber();
        System.out.println("ALICE EXPONENT AND COMPUTED EXPONENTIAL: " + Alice.getSelfX() + " " + Alice.getSelfExponential());
        BigInteger alphaY = Bob.ComputeExponentialAndRandomNumber();
        System.out.println("BOB EXPONENT AND COMPUTED EXPONENTIAL: " + Bob.getSelfX() + " " + Bob.getSelfExponential() + "\n");

        Bob.setOtherExponential(alphaX);
        Alice.setOtherExponential(alphaY);

        Alice.setOtherPublicKey(Bob.getSelfPublicKey());
        Bob.setOtherPublicKey(Alice.getSelfPublicKey());

        Bob.SharedKeyCalculation();
        System.out.println("BOB CALCULATED SHARED KEY K AS:\n" + Bob.getSharedKey() + "\n");
        Message answerFromBob = Bob.CipherSignAndConcatenate(true);

        Alice.SharedKeyCalculation();
        System.out.println("ALICE CALCULATED SHARED KEY K AS:\n" + Alice.getSharedKey() + "\n");
        Alice.DecryptionAndVerification(answerFromBob);

        Message answerFromAlice = Alice.CipherSignAndConcatenate(false);
        Bob.DecryptionAndVerification(answerFromAlice);
        System.out.println("SIMULATION FINISHED SUCCESSFULLY");
    }
}