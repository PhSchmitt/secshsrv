import engine.SecretShare;
import engine.SecretShare.PublicInfo;
import engine.SecretShare.ShareInfo;
import exceptions.SecretShareException;
import math.BigIntUtilities;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by philipp on 29.06.15.
 * based on Implementation of Tim Tiemens
 */
public class Secshsrv {

    final static int portNumber = 8080;
    final static String splitCharacter = "|";

    public static void main(String[] args) {
        String incomingdata = getDataFromSocket();
        Integer totalNumberOfShares = extractTotalNumberOfShares(incomingdata);
        Integer numberOfSharesToCombine = extractNumberOfSharesToCombine(incomingdata);
        List<String> splitInputString = splitStringAtChar(incomingdata);
        CombineInput input = CombineInput.parse(totalNumberOfShares, numberOfSharesToCombine, splitInputString);
        CombineOutput output = input.output();
        System.out.println(output.showPlaintext());
    }

    private static String getDataFromSocket()
    {
        String inputString ="";
        try {
            ServerSocket serverSocket = new ServerSocket(portNumber);
            Socket clientSocket = serverSocket.accept();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));
            String inputLine;

            while ((inputLine = in.readLine()) != null) {
                inputString += inputLine;
            }
            clientSocket.close();
            serverSocket.close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return inputString;
    }

    static Integer extractNumberOfSharesToCombine(String incomingdata)
    {
        //numberofsharestocombine (k) is on 2nd position: incomingdata=n|k|modulus|$Shares|
        String incomingdataWithoutN = incomingdata.substring(incomingdata.indexOf(splitCharacter) + 1);
        String kstring = incomingdataWithoutN.substring(0, incomingdataWithoutN.indexOf(splitCharacter));
        return new Integer(kstring);
    }

    static Integer extractTotalNumberOfShares(String incomingdata)
    {
        //totalnumberofshares (n) is on first position: incomingdata=n|k|modulus|$Shares|
        String nstring = incomingdata.substring(0, incomingdata.indexOf(splitCharacter));
        return new Integer(nstring);
    }

    static List<String> splitStringAtChar(String incomingdata)
    {
        List<String> result = new ArrayList<>();
        List<Integer> splitCharIndizes = new ArrayList<>();
        for (int index = incomingdata.indexOf(splitCharacter);
             index >= 0;
             index = incomingdata.indexOf(splitCharacter, index + 1))
        {
            splitCharIndizes.add(index);
        }
        for (int j = 0; j < splitCharIndizes.size(); j++) {
            Integer i = splitCharIndizes.get(j);
            //don't consider the first two as they are headers: n|k|modulus|$Shares|
            //extract shares out of |share0|share1|...|
            //the last splitChar marks the end of the Stream
            if (i > splitCharIndizes.get(1) && (j < splitCharIndizes.size() - 1))
            {
                result.add(incomingdata.substring(i + 1, splitCharIndizes.get(j + 1)));
            }
        }
        return result;
    }

    public static BigInteger parseBigInteger(String value) {
        BigInteger ret;
        if (BigIntUtilities.Checksum.couldCreateFromStringMd5CheckSum(value)) {
            try {
                ret = BigIntUtilities.Checksum.createBigInteger(value);
            } catch (SecretShareException e) {
                String m = "Failed to parse 'bigintcs:' because: " + e.getMessage();
                throw new SecretShareException(m, e);
            }
        } else {
            try {
                ret = new BigInteger(value);
            } catch (NumberFormatException e) {
                String m = "Failed to parse integer because: " + e.getMessage();
                throw new SecretShareException(m, e);
            }
        }

        return ret;
    }

    public static class CombineInput
    {

        private final List<ShareInfo> shares = new ArrayList<>();
        private Integer k           = null;
        // optional:  if null, then do not use modulus
        private BigInteger modulus = null;
        // optional: for combine, we don't need n, but you can provide it
        private Integer n           = null;

        // not an input.  used to cache the PublicInfo, so that after the first ShareInfo is
        //  created with this PublicInfo, then they are all created with the same PublicInfo
        private PublicInfo publicInfo;

        // constructor
        public static CombineInput parse(Integer totalNumberOfShares,
                                         Integer numberOfSharesNeededToCombine,
                                         //Integer modulus,
                                         List<String> allShares)
        {
            CombineInput ret = new CombineInput();

                    ret.k = numberOfSharesNeededToCombine;
                    ret.n = totalNumberOfShares;
                    //TODO we don't use modulus for performance reasons
//                    ret.modulus = modulus;
                                    ret.modulus = null;

            SecretShare.PublicInfo publicInfo = new SecretShare.PublicInfo(ret.n, ret.k, ret.modulus,"");
            for (int i = 0; i < allShares.size(); i++) {
                String shareStr = allShares.get(i);
                BigInteger shareInt = parseBigInteger(shareStr);
                //the combine implementation requires the share count to start with 1 and not 0 !!!
                ret.addIfNotDuplicate(new ShareInfo(i + 1, shareInt, publicInfo));
            }
            if (ret.shares.size() < ret.k)
            {
                throw new SecretShareException("k set to " + ret.k + " but only " +
                        ret.shares.size() + " shares provided");
            }
            return ret;
        }

        private void addIfNotDuplicate(ShareInfo add)
        {
            boolean shouldadd = true;
            for (ShareInfo share : this.shares)
            {
                if (share.getX() == add.getX())
                {
                    if (! share.getShare().equals(add.getShare()))
                    {
                        throw new SecretShareException("share x:" + share.getX() +
                                " was entered with two different values " +
                                "(" + share.getShare() + ") and (" +
                                add.getShare() + ")");
                    }
                    else
                    {
                        shouldadd = false;
                    }
                }
                else if (share.getShare().equals(add.getShare()))
                {
                    throw new SecretShareException("duplicate share values at x:" +
                            share.getX() + " and x:" +
                            add.getX());
                }
            }
            if (shouldadd)
            {
                this.shares.add(add);
            }
        }


        private PublicInfo constructPublicInfoFromFields(String where)
        {
            return new SecretShare.PublicInfo(this.n, this.k, this.modulus,
                    "MainCombine:" + where);
        }

        public CombineOutput output()
        {
            CombineOutput ret = new CombineOutput();

            // it is a "copy" since it should be equal to this.publicInfo
            SecretShare.PublicInfo copyPublicInfo = constructPublicInfoFromFields("output");
            SecretShare secretShare = new SecretShare(copyPublicInfo);
            SecretShare.CombineOutput combine = secretShare.combine(shares);
            ret.secret = combine.getSecret();
            return ret;
        }
    }

    public static class CombineOutput
    {
        private BigInteger secret;

        public String showPlaintext() {
            return BigIntUtilities.Human.createHumanString(secret);
        }

    }

}


