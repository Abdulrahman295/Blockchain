import java.util.Date;
import java.util.HashMap;
import java.util.Map.Entry;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import com.google.gson.GsonBuilder;
import java.security.*;

// create a basic block
class Block{
    public String hash;
    public String prevHash;
    public ArrayList<Transaction> transactions = new ArrayList<Transaction>();
    public long timeStamp;
    private int nonce;

    Block(String prevHash){
        this.prevHash = prevHash;
        timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    //Calculate new hash based on blocks contents
    public String calculateHash(){
        // provide SHA-256 with a combination of d timeStamp , nonce and prevHash.
        String hash = StringUtil.applySHA256(Long.toString(timeStamp)+ Integer.toString(nonce) + prevHash);
        return hash;
    }

    // proof of work mining to validate new blocks.
    public void mineBlock(int difficulty){
        // create a string of leading 0s that a hash must have with length of difficulty
        String target = new String(new char[difficulty]).replace('\0', '0');

        // keep changing nonce until we get a hash that has the same number of leading 0s as difficulty
        while(!hash.substring(0, difficulty).equals(target)){
            nonce++;
            hash = calculateHash();
        }

        // print the hash
        System.out.println("Block Mined!!! : " + hash);
    }

    // add new transactions to the block
    public boolean addTransaction(Transaction transaction){
        if(transaction == null)
            return false;

        // if the current block is genesis block then add the transaction to it without any validation
        if((prevHash == "0")){
            transactions.add(transaction);
            return true;
        }

        // if not genesis block then validate the transaction first
        if(transaction.processTransaction() != true){
            System.out.println("Transaction failed to process. Discarded.");
            return false;
        } 
        transactions.add(transaction);
        System.out.println("Transaction Successfully added to Block");
		return true;
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
class StringUtil{
    // create a digital signature for each transaction
    public static String applySHA256(String input){
        try {
            // get Instance of SHA-256 algorithm
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            //get the bytes of input string and apply UTF-8 coding , then apply SHA-256 to hash it in form of array of unique 32 bytes.
            byte[] hash = digest.digest(input.getBytes("UTF-8"));

            // hexstring will contain the resultant hash array in form of hexadicemal
            StringBuffer hexString = new StringBuffer();

            for(int i = 0; i < hash.length; i++){
                // get unsigned byte from hash array and convert it to hexadecimal string
                String hexDigit = Integer.toHexString(hash[i]);

                //make sure that each byte is a two-digit hexadecimal
                if(hexDigit.length() == 1)
                    hexString.append('0');
                hexString.append(hexDigit);
            }

            return hexString.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // returns signature as bytes
    public static byte[] applyECDSASig(PrivateKey privateKey, String input){
        Signature dsa;
        byte [] result = new byte[0];
        try {
            dsa = Signature.getInstance("ECDSA","BC"); 

            // initialize the Signature with sender private key
            dsa.initSign(privateKey);

            // get data from input string and sign it
            byte[] inputBytes = input.getBytes();
            dsa.update(inputBytes);

            // return the signature in form of byte array
            result = dsa.sign();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return result;
    }

    // verify the data isn't tampered with
    public static boolean verifyECDSASig(PublicKey publicKey, String data, byte[] signature) {
        try {
            Signature ecVarification = Signature.getInstance("ECDSA","BC");

            // initialize the Signature Varification with sender private key
            ecVarification.initVerify(publicKey);

            // generate the Signature from data
            ecVarification.update(data.getBytes());

            // check if the signature is valid
             return ecVarification.verify(signature);


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getStringFromKey(Key key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Wallet{
    // The private key is used to sign the data and the public key can be used to verify its integrity.
    public PublicKey publicKey;
    public PrivateKey privateKey;
    public HashMap<String, TransactionOutput> My_UTOXs = new HashMap<String,TransactionOutput>();

    Wallet(){
        generateKeyPair();	
    }

    public void generateKeyPair(){
        try {
            // create a keyGenerator that uses Elliptic Curve Digital Signature Algorithm provided by BouncyCastle
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA","BC"); 

            // initialize a random number generator for our keyGen
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            // specify the curve parameters for ECDS algorithm
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");

            // generate the key pair
            keyGen.initialize(ecSpec, random);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
	        publicKey = keyPair.getPublic();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // return balance and stores the UTXOs owned by this wallet in My_UTOXs
    public float getBalance(){
        float total = 0;
        for (HashMap.Entry<String, TransactionOutput> item: Chain.UTXOs.entrySet()){
            TransactionOutput UTXO = item.getValue();
            if(UTXO.isMine(publicKey)){
                My_UTOXs.put(UTXO.id, UTXO);
                total += UTXO.value;
            }
        }
        return total;
    }

    // send funds from this wallet to the recipient
    public Transaction sendFunds(PublicKey _recipient,float value){
        // check if the wallet has enough funds to send
        if(getBalance() < value){
            System.out.println("#Not Enough funds to send transaction. Transaction Discarded.");
            return null;
        }

        // get the required inputs from the My_UTOXs to send the transaction
        ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
        float total = 0;

        for(HashMap.Entry<String, TransactionOutput> item: My_UTOXs.entrySet()){
            // stop if we have enough to send the transaction
            if(total > value)
                break;
            TransactionOutput UTXO = item.getValue();
            inputs.add(new TransactionInput(UTXO.id));
        }

        // remove the referenced UTXOs from the My_UTOXs
        for(TransactionInput i : inputs){
            My_UTOXs.remove(i.transactionOutputID);
        }

        // generate the transaction and
        Transaction newTrans = new Transaction(publicKey, _recipient, value, inputs);
        newTrans.generateSignature(privateKey);
        return newTrans;

    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// TransactionOutput class will be used to store the new transactions
class TransactionOutput{
    public String id;
    public PublicKey reciepient;
    public float value;
    public String parentTransactionID;

    TransactionOutput(float value, PublicKey reciepient, String parentTransactionID){
        this.value = value;
        this.reciepient = reciepient;
        this.parentTransactionID = parentTransactionID;
        this.id = StringUtil.applySHA256(StringUtil.getStringFromKey(reciepient) + Float.toString(value) + parentTransactionID);
    }

    //Check if coin belongs to you
	public boolean isMine(PublicKey publicKey) {
		return (publicKey == reciepient);
	}
}

// TransactionInput class will be used to reference TransactionOutputs that have not yet been spent.
class TransactionInput { 
    public String transactionOutputID;
    public TransactionOutput UTXO;

    TransactionInput(String transactionOutputID){
        this.transactionOutputID = transactionOutputID;
    }
}

// Transaction class will be used to send funds from one wallet to another.
class Transaction {
    private static int secquence = 0; 
    public PublicKey sender;
    public PublicKey reciepient;
    public float value;
    public byte[] signature;
    public String transactionID;

    // list of inputs and outputs
    public ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
	public ArrayList<TransactionOutput> outputs = new ArrayList<TransactionOutput>();
    
    Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs){
        this.sender = from;
        this.reciepient = to;
        this .inputs = inputs;
        this.value = value;
    }

    private String generateTransactionID(){
        // change secquence for each transaction to make each id unique
        secquence++;

        // generate a hash for each transaction
        return StringUtil.applySHA256(
            StringUtil.getStringFromKey(sender) +
            StringUtil.getStringFromKey(reciepient)+
            Float.toString(value) +
            Integer.toString(secquence)
        );
    }

    public void generateSignature(PrivateKey privateKey){
        String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient) + Float.toString(value); 
        signature = StringUtil.applyECDSASig(privateKey, data);
    }

    // verify the data isn't tampered with
    public boolean verifiySignature() {
        String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient) + Float.toString(value); 
        return StringUtil.verifyECDSASig(sender, data, signature);
    }

    public boolean processTransaction(){
        if(verifiySignature() == false ){
            System.out.println("#Transaction Signature failed to verify");
			return false;
        }

        // get the reference to the transaction output from the list of unspent transactions
        for(TransactionInput i : inputs){
            i.UTXO = Chain.UTXOs.get(i.transactionOutputID);
        }

        //Checks if transaction is valid:
		if(getInputsValue() < Chain.minimumTransaction) {
			System.out.println("Transaction Inputs too small: " + getInputsValue());
			System.out.println("Please enter the amount greater than " + Chain.minimumTransaction);
			return false;
		}

        // find the left over value
        float leftOver = getInputsValue() - value;

        // generate a new id for the transaction after it is processed
        transactionID = generateTransactionID();

        // add the result of the process to the outputs list , then add these outputs to the unspent list
        outputs.add(new TransactionOutput(value, reciepient, transactionID));
        outputs.add(new TransactionOutput(leftOver, sender, transactionID));
        for(TransactionOutput o : outputs){
            Chain.UTXOs.put(o.id, o);
        }

        // remove processed transactions from the unspent list
        for(TransactionInput i : inputs){
            if(i.UTXO == null)
                continue;

            Chain.UTXOs.remove(i.transactionOutputID);
        }
        
        return true;
    }

    // returns sum of input values
    public float getInputsValue(){
        float total = 0;

        for(TransactionInput i : inputs){
            // if it doesn't refer to any transaction output then skip it
            if(i.UTXO == null) 
                continue;
            total += i.UTXO.value;
        }

        return total;
    }

    // returns sum of output values
    public float getOutputsValue(){
        float total = 0;

        for(TransactionOutput o : outputs){
            total += o.value;
        }

        return total;
    }   
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

public class Chain {

    // creat a blockchain
    public static ArrayList<Block> blockchain = new ArrayList<Block>(); 

    // create a map <id, transaction> of all unspent transactions to process new transactions faster
    public static HashMap<String,TransactionOutput> UTXOs = new HashMap<String,TransactionOutput>();

    // set initial difficulty of mining
    public static int difficulty = 3;

    // set minimum transaction value
    public static float minimumTransaction = 0.1f;

    // create wallets 
    public static Wallet walletA;
	public static Wallet walletB;

    // function to check integrity of our blockchain.
    public static Boolean isChainValid() {
        // check the integrity of each block in our chain
        for(int i = 1; i<blockchain.size(); i++){
            Block prevBlock = blockchain.get(i-1);
            Block currentBlock = blockchain.get(i);
            String hashTarget = new String( new char[difficulty]).replace('\0', '0');

            // compare registered hash and calculated hash:
            if(!currentBlock.hash.equals(currentBlock.calculateHash())){
                System.out.println("Current Hashes not equal");			
			    return false;
            }

            // compare previous hash and registered previous hash
            if(!currentBlock.prevHash.equals(prevBlock.hash)){
                System.out.println("Previous Hashes not equal");
			    return false;
            }

            // check if hash is solved
            if(!currentBlock.hash.substring(0, difficulty).equals(hashTarget)){
                System.out.println("This block hasn't been mined");
				return false;
            }
            
            // loop throught transactions of each block in the chain and verify them after checking the block integrity, we ignore the genesis block
            for(int t = 0; t <currentBlock.transactions.size(); t++) {
                Transaction currentTransaction = currentBlock.transactions.get(t);
                
                if(!currentTransaction.verifiySignature()){
                    System.out.println("#Signature on Transaction(" + t + ")"+ "At Block ("+ i + ") is Invalid");
					return false; 
                }

                if(currentTransaction.getInputsValue() != currentTransaction.getOutputsValue()){
                    System.out.println("#Inputs are note equal to outputs on Transaction(" + t + ")"+ "At Block ("+ i + ")");
					return false; 
                }

            }

        }
        return true;
    }

    // add new block to the chain
    public static void addBlock(Block newBlock){
        newBlock.mineBlock(difficulty);
        blockchain.add(newBlock);
    }
    public static void main(String[] args) throws Exception {
        //Setup Bouncey castle as a Security Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); 

       //Create wallets:
		walletA = new Wallet();
		walletB = new Wallet();		
		Wallet coinbase = new Wallet(); // used to initially send coins to walletA

        // create genesis Block
        System.out.println("Creating and Mining Genesis block... ");
        Block genesisBlock = new Block("0");

        // create genesis transaction, which sends 100 coins to walletA
        Transaction genesisTransaction = new Transaction(coinbase.publicKey, walletA.publicKey, 100f, null);
        genesisTransaction.generateSignature(coinbase.privateKey);
        genesisTransaction.transactionID = "0";
        genesisTransaction.outputs.add(new TransactionOutput(100f, walletA.publicKey, genesisTransaction.transactionID));
        UTXOs.put(genesisTransaction.outputs.get(0).id, genesisTransaction.outputs.get(0));

        // add the genesis transaction to the genesis block
        genesisBlock.addTransaction(genesisTransaction);
        addBlock(genesisBlock);

        // testing the genesis transaction
        System.out.println("\nWalletA's balance is: " + walletA.getBalance());

        // create a new block where we make a transaction from walletA to walletB 
        System.out.println("Creating and Mining block1... ");
        Block block1 = new Block(genesisBlock.hash);

        // create a transaction, which sends 40 coins from walletA to walletB
        Transaction transaction1 = walletA.sendFunds(walletB.publicKey,40f);

        //add transaction1 to block1
        block1.addTransaction(transaction1);
        addBlock(block1);
        
        // testing the result transaction1
        System.out.println("\nWalletA's balance is: " + walletA.getBalance());
		System.out.println("WalletB's balance is: " + walletB.getBalance());
		
    }
}
