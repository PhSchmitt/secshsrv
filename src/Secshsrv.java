import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;


import engine.SecretShare;
import engine.SecretShare.PublicInfo;
import engine.SecretShare.ShareInfo;
import exceptions.SecretShareException;
import math.BigIntUtilities;

/**
 * Created by philipp on 29.06.15.
 * based on Implementation of Tim Tiemens
 */
public class Secshsrv {

    final static int portNumber = 8080;
    final static String splitCharacter = "|";

    public void main(String[] args) {
        String incomingdata = getDataFromSocket();
        Integer numberOfSharesToCombine = extractNumberOfSharesToCombine(incomingdata);
        Integer totalNumberOfShares = extractTotalNumberOfShares(incomingdata);
        List<String> splitInputString = splitStringAtChar(incomingdata);
        CombineInput input = CombineInput.parse(numberOfSharesToCombine,totalNumberOfShares,splitInputString);
        System.out.println(incomingdata);
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
        String tmp1 = incomingdata.substring(incomingdata.indexOf(splitCharacter)+1);
        String tmp2 = tmp1.substring(0,tmp1.indexOf(splitCharacter)-1);
        return new Integer(tmp2);
    }

    static Integer extractTotalNumberOfShares(String incomingdata)
    {
        String tmp1 = incomingdata.substring(incomingdata.indexOf(splitCharacter)+1);
        String tmp2 = tmp1.substring(tmp1.indexOf(splitCharacter)+1);
        String tmp3 = tmp2.substring(0,tmp2.indexOf(splitCharacter)-1);
        return new Integer(tmp3);
    }

    List<String> splitStringAtChar(String incomingdata)
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
            //don't consider before index 0 (n), 1 (k) and 2 (modulus)
            //the last splitChar marks the end of the Stream
            if (i>1 && j < splitCharIndizes.size()-1)
            {
                result.add(incomingdata.substring(i+1,splitCharIndizes.get(j)-1));
            }

        }
        return result;
    }

    public static class CombineInput
    {
        // ==================================================
        // instance data
        // ==================================================

        // required arguments:
        private Integer k           = null;

        private final List<ShareInfo> shares = new ArrayList<>();

        // optional:  if null, then do not use modulus
        // default to 384-bit
        private BigInteger modulus = SecretShare.getPrimeUsedFor384bitSecretPayload();

        // optional: for combine, we don't need n, but you can provide it
        private Integer n           = null;


        // not an input.  used to cache the PublicInfo, so that after the first ShareInfo is
        //  created with this PublicInfo, then they are all created with the same PublicInfo
        private PublicInfo publicInfo;

        // ==================================================
        // constructors
        // ==================================================
        public static CombineInput parse(Integer numberOfSharesNeededToCombine,
                                         Integer totalNumberOfShares,
                                         List<String> allShares)
        {
            CombineInput ret = new CombineInput();

                    ret.k = numberOfSharesNeededToCombine;
                    ret.n = totalNumberOfShares;
                    //TODO we don't use modulus for performance reasons
//                    ret.modulus = parseBigInteger("m", modulus);
                                    ret.modulus = null;

            SecretShare.PublicInfo publicInfo = new SecretShare.PublicInfo(ret.n, ret.k, ret.modulus,"");
            for (int i = 0; i < allShares.size(); i++) {
                String shareStr = allShares.get(i);
                BigInteger shareInt;
                if (BigIntUtilities.Checksum.couldCreateFromStringMd5CheckSum(shareStr))
                {
                    shareInt = BigIntUtilities.Checksum.createBigInteger(shareStr);
                }
                else if (BigIntUtilities.Hex.couldCreateFromStringHex(shareStr))
                {
                    shareInt = BigIntUtilities.Hex.createBigInteger(shareStr);
                }
                else
                {
                    shareInt = new BigInteger(shareStr);
                }
                ret.addIfNotDuplicate(new ShareInfo(i,shareInt,publicInfo));
            }
            if (ret.shares.size() < ret.k)
            {
                throw new SecretShareException("k set to " + ret.k + " but only " +
                        ret.shares.size() + " shares provided");
            }

            return ret;
        }

        private void processStdin(InputStream in,
                                  PrintStream out)
        {
            try
            {
                processStdinThrow(in, out);
            }
            catch (IOException e)
            {
                throw new SecretShareException("IOException reading stdin", e);
            }
        }

        // examples of the kinds of lines we look for:

        //  n = 6
        //  k = 3
        //  modulus = 830856716641269307206384693584652377753448639527
        //  modulus = bigintcs:000002-dba253-6f54b0-ec6c27-3198DB
        //  Share (x:1) = 481883688219928417596627230876804843822861100800
        //  Share (x:2) = 481883688232565050752267350226995441999530323860
        //  Share (x:1) = bigintcs:005468-697323-cc48a7-8f1f87-996040-4d07d2-3da700-9C4722
        //  Share (x:2) = bigintcs:005468-69732d-4e02c5-7b11d2-9d4426-e26c88-8a6f94-9809A9
        private void processStdinThrow(InputStream in,
                                       PrintStream out)
                throws IOException
        {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = br.readLine()) != null)
            {
                if (line.startsWith("n ="))
                {
                    this.n = parseEqualInt("n", line);
                }
                else if (line.startsWith("k ="))
                {
                    this.k = parseEqualInt("k", line);
                }
                else if (line.startsWith("modulus ="))
                {
                    this.modulus = parseEqualBigInt("modulus", line);

                }
                else if (line.startsWith("Share ("))
                {
                    SecretShare.ShareInfo share = parseEqualShare("share", line);
                    addIfNotDuplicate(share);
                }
                else
                {
                    // There are lots of lines we do not process.
                    // For now, just ignore them.
                }
            }
        }

        private void addIfNotDuplicate(ShareInfo add)
        {
            boolean shouldadd = true;
            for (ShareInfo share : this.shares)
            {
                if (share.getX() == add.getX())
                {
                    // dupe
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


        /**
         *
         * @param fieldname description of source of data
         * @param line is "standard format for share", example:
         *   Share (x:2) = 481883688232565050752267350226995441999530323860
         * @return ShareInfo (integer and big integer)
         */
        private ShareInfo parseEqualShare(String fieldname,
                                          String line)
        {
            if (this.publicInfo == null)
            {
                this.publicInfo = constructPublicInfoFromFields("parseEqualShare");
            }

            BigInteger s = parseEqualBigInt(fieldname, line);
            int x = parseXcolon(line);
            return new ShareInfo(x, s, this.publicInfo);
        }

        private PublicInfo constructPublicInfoFromFields(String where)
        {
            return new SecretShare.PublicInfo(this.n, this.k, this.modulus,
                    "MainCombine:" + where);
        }

        //  Share (x:2) = bigintcs:005468-69732d-4e02c5-7b11d2-9d4426-e26c88-8a6f94-9809A9
        private int parseXcolon(String line)
        {
            String i = after(line, ":");
            int end = i.indexOf(")");
            i = i.substring(0, end);

            return Integer.valueOf(i);
        }

        private BigInteger parseEqualBigInt(String fieldname,
                                            String line)
        {
            String s = after(line, "=");
            if (BigIntUtilities.Checksum.couldCreateFromStringMd5CheckSum(s))
            {
                return BigIntUtilities.Checksum.createBigInteger(s);
            }
            else if (BigIntUtilities.Hex.couldCreateFromStringHex(s))
            {
                return BigIntUtilities.Hex.createBigInteger(s);
            }
            else
            {
                return new BigInteger(s);
            }
        }

        private String after(String line,
                             String lookfor)
        {
            return line.substring(line.indexOf(lookfor) + 1).trim();
        }

        private Integer parseEqualInt(String fieldname,
                                      String line)
        {
            String s = after(line, "=");
            return Integer.valueOf(s);
        }

        private static void checkRequired(String argname,
                                          Object obj)
        {
            if (obj == null)
            {
                throw new SecretShareException("Argument '" + argname + "' is required.");
            }
        }

        // ==================================================
        // public methods
        // ==================================================
        public CombineOutput output()
        {
            CombineOutput ret = new CombineOutput();
            ret.combineInput = this;

            // it is a "copy" since it should be equal to this.publicInfo
            SecretShare.PublicInfo copyPublicInfo = constructPublicInfoFromFields("output");

            SecretShare secretShare = new SecretShare(copyPublicInfo);

            SecretShare.CombineOutput combine = secretShare.combine(shares);

            ret.secret = combine.getSecret();

            return ret;
        }

        // ==================================================
        // non public methods
        // ==================================================
    }

    public static class CombineOutput
    {
        private BigInteger secret;

        @SuppressWarnings("unused")
        private SecretShare.CombineOutput combineOutput;
        @SuppressWarnings("unused")
        private CombineInput combineInput;

//        public void print(PrintStream out)
//        {
//            //final SecretShare.PublicInfo publicInfo = combineOutput.getPublicInfo();
//
//            out.println("Secret Share version " + Main.getVersionString());
//            //field(out, "Date", publicInfo.getDate());
//            //field(out, "UUID", publicInfo.getUuid());
//            //field(out, "Description", publicInfo.getDescription());
//
//            out.println("secret.number = '" + secret + "'");
//            String s = BigIntUtilities.Human.createHumanString(secret);
//            out.println("secret.string = '" + s + "'");
//
//        }

        // ==================================================
        // instance data
        // ==================================================

        // ==================================================
        // constructors
        // ==================================================

        // ==================================================
        // public methods
        // ==================================================

        // ==================================================
        // non public methods
        // ==================================================
    }

    public static BigInteger parseBigInteger(String value)
    {
        BigInteger ret;
        if (BigIntUtilities.Checksum.couldCreateFromStringMd5CheckSum(value))
        {
            try
            {
                ret = BigIntUtilities.Checksum.createBigInteger(value);
            }
            catch (SecretShareException e)
            {
                String m = "Failed to parse 'bigintcs:' because: " + e.getMessage();
                throw new SecretShareException(m, e);
            }
        }
        else
        {
            try
            {
                ret = new BigInteger(value);
            }
            catch (NumberFormatException e)
            {
                String m = "Failed to parse integer because: " + e.getMessage();
                throw new SecretShareException(m, e);
            }
        }

        return ret;
    }

    public static Integer parseInt(String value)
    {
        Integer ret;
        try
        {
            ret = Integer.valueOf(value);
        }
        catch (NumberFormatException e)
        {
            String m = "The argument of '" + value + "' " +
                    "is not a number.";
            throw new SecretShareException(m, e);
        }
        return ret;
    }

}


