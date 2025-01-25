import java.util.HashMap;
import java.util.Map;


public class Vigenere {

    /***********************************************************************************************
     * TASK 1: function for creating the extended key for vigenere cipher based on plain text length
     */
    public static char[] CreateKey(String key, int plainTextSize) {
        StringBuilder extendedKey = new StringBuilder(); //represents our extended key 

        // append given key into extendedKey in size of the plainText
        for (int i = 0; i < plainTextSize; i++) 
            extendedKey.append(key.charAt(i % key.length()));
        
        return extendedKey.toString().toCharArray(); //return char array 
    }
    

    /***********************************************************************************************
     * TASK 1: function that encrypts given plaintext with specified key using vigenere cipher
     */
    public static String VigenereEncrypt(String plainText, String key) {
        char[] plainTextArray = plainText.toCharArray();
        char[] extendedKey = CreateKey(key, plainText.length()); //extend the key to fit plaintext length
        char defaultOffset = 'A'; //represents the starting offset of each character (A value) 
        // iterate over plaintext array and perform encryption formula
        for(int i = 0; i < plainTextArray.length; i++) 
            //calculate enryption with formula (P[i] + K[i]) + 26) % 26 , adding 26 because module will fail if performed on negative value
            plainTextArray[i] = (char)((((plainTextArray[i] - defaultOffset) + (extendedKey[i] - defaultOffset) + 26) % 26) + defaultOffset);

        return new String(plainTextArray);
    }


    /***********************************************************************************************
     * TASK 1: function that decrypts given ciphertext with specified key using vigenere cipher
     */
    public static String VigenereDecrypt(String cipherText, String key) {
        char[] cipherTextArray = cipherText.toCharArray();
        char[] extendedKey = CreateKey(key, cipherText.length()); //extend the key to fit plaintext length
        char defaultOffset = 'A'; //represents the starting offset of each character (A value) 
        // iterate over ciphertext array and perform decryption formula
        for(int i = 0; i < cipherTextArray.length; i++) 
            //calculate deryption with formula (P[i] - K[i]) + 26) % 26 , adding 26 because module will fail if performed on negative value
            cipherTextArray[i] = (char)((((cipherTextArray[i] - defaultOffset) - (extendedKey[i] - defaultOffset) + 26) % 26) + defaultOffset);
        
        return new String(cipherTextArray);
    }


    /***********************************************************************************************
     * TASK 2: function that maps each letter to its frequency in Vigenere ciphertext
     */
    public static Map<Character, Double> CreateFrequencyDict(char[] plaintext) {
        Map<Character, Double> letterFrequency = new HashMap<>(); //represent our letter frequency dict
        
        // initialize each letter with starting value of 0
        for (char letter = 'A'; letter <= 'Z'; letter++) 
            letterFrequency.put(letter, 0.0); //add letter - frequency pairs into dict

        // iterate over plaintext and calculate letter occurrences
        for (int i = 0; i < plaintext.length; i++) {
            if (plaintext[i] != '\0') { //we check if value is not null
                char currentChar = plaintext[i];

                // we check first that given letter is uppercase valid letter
                if (currentChar >= 'A' && currentChar <= 'Z')
                    letterFrequency.put(currentChar, (letterFrequency.get(currentChar) + 1)); //increment letter in our dict
            }
        }
        return letterFrequency;
    }


    /***********************************************************************************************
     * TASK 3: function for calculating the IC value of given subtext in plaintext (with K values)
     */
    public static double FindIC(char[] text) {
        Map<Character, Double> letterFrequency = CreateFrequencyDict(text); //create our frequency dict
        double IC = 0; //initialize the IC value

        // iterate over frequency dict and sum all letters frequency values
        for (Character letter : letterFrequency.keySet()) 
            IC += letterFrequency.get(letter) * (letterFrequency.get(letter) - 1); //calculate the numerator
        
        IC = IC / ((text.length * (text.length - 1)) / 26); //finally we divide by the denominator

        return IC;
    }


    /***********************************************************************************************
     * TASK 3: function that find the most probable key length using index of coincidence based on given text 
     */
    public static int GetKeyLength(char[] text) {
        double[] resultsArray = new double[15]; //represents the final results array of each K's IC value
        
        // iterate over each possible K value, splite the text into K subtexts using module operator,
        // for each subtext we calculate IC value, for each K calculate avg IC value of subtexts.
        for (int k = 1; k <= 15 ; k++) {
            char[][] subtextsArray = new char[k][]; //initialize array for each subtext
            int[] subtextsLength = new int[k]; //initialize array for lengths of each subtext

            // split the text into k subtexts
            for (int i = 0; i < text.length; i++) {
                int subIndex = i % k; //calculate the number of letters for each possible module value
                subtextsLength[subIndex]++; //increment the coresponding index in length array
            }
            // initialize subtextsArray with correct lengths
            for (int i = 0; i < k; i++) 
                subtextsArray[i] = new char[subtextsLength[i]];

            // fill subtextsArray with characters based on module values
            int[] indicesArray = new int[k]; //temorary array for holding the next index for each subtext array
            for (int i = 0; i < text.length; i++) {
                int subIndex = i % k; //calculate the number of letters for each possible module value
                subtextsArray[subIndex][indicesArray[subIndex]++] = text[i]; //insert letter into coresponding index in subtext array
            }

            // calculate IC for each subtext array and calculate the average IC
            double sumIC = 0; //temp variable to hold sum of all IC values
            for (int i = 0; i < k; i++) 
                sumIC += FindIC(subtextsArray[i]); //sum all IC values for subtext arrays
            resultsArray[k - 1] = sumIC / k; //calculate average IC for current K
        }

        // find K with the maximum average IC
        double maxIC = 0; //represents max IC value
        int maxK = 0; //represents the max K value of text
        for (int i = 0; i < resultsArray.length; i++) {
            if (maxIC < resultsArray[i]) {
                maxIC = resultsArray[i]; //set new maximum value
                maxK = i + 1; //set the maximum K 
            }
        }

        return maxK; //returning the key length with the highest probability of success
    }


    /***********************************************************************************************
     * TASK 4: function that finds the correct cipher key used to encrypt the original plaintext using given ciphertext
     */
    public static String GetCipherKey(char[] text) {
        // initialize the dictionaries for english letter frequency
        // Link: https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
        Map<Character, Double> englishFrequency = Map.ofEntries(
            Map.entry('A', 8.167), Map.entry('B', 1.492), Map.entry('C', 2.782),
            Map.entry('D', 4.253), Map.entry('E', 12.702), Map.entry('F', 2.228),
            Map.entry('G', 2.015), Map.entry('H', 6.094), Map.entry('I', 6.966),
            Map.entry('J', 0.253), Map.entry('K', 0.772), Map.entry('L', 4.025),
            Map.entry('M', 2.406), Map.entry('N', 6.749), Map.entry('O', 7.507),
            Map.entry('P', 1.929), Map.entry('Q', 0.095), Map.entry('R', 5.987),
            Map.entry('S', 6.327), Map.entry('T', 9.056), Map.entry('U', 2.758),
            Map.entry('V', 0.978), Map.entry('W', 2.360), Map.entry('X', 0.250),
            Map.entry('Y', 1.974), Map.entry('Z', 0.074)
        );

        // create the text matrix according to the key length
        int keyLength = GetKeyLength(text); //get the probable key length
        int numOfRows = (text.length % keyLength == 0) ? (text.length / keyLength) : (text.length / keyLength) + 1; //calcuate the number of rows needed
        char[] cipherKey = new char[keyLength]; //represents the cipher key used to encrypt the cipertext
        char[][] textMatrix = new char[numOfRows][keyLength]; //represents the text matrix where each row is size of key length
        int textIndex = 0; //represents the text array index 

        // initialize the text matrix all the letters from given text array
        for(int i = 0; i < numOfRows; i++) {
            for(int j = 0; j < keyLength; j++) {
                if (textIndex < text.length) //to avoid index out of bound error we check if we finsihed adding all array letters
                    textMatrix[i][j] = text[textIndex++]; //insert letter into matrix
            }
        }
        
        // iterating over each column, for each column calculating the maximum correlation to determine the cipher letter for each column
        for(int i = 0; i < keyLength; i++) {
            char[] currentColumn = new char[textMatrix.length]; //represents signle column in our text matrix to measure the correlation

            // iterate over each row to get the element in the specified column
            for (int j = 0; j < textMatrix.length; j++) 
                currentColumn[j] = textMatrix[j][i]; //copy matrix column valus to our current column
            
            Map<Character, Double> columnFrequency = CreateFrequencyDict(currentColumn); //calculate the letter frequency in current column
            char defaultOffset = 'A'; //represents the starting offset of each character (A value) 
            char bestFit = defaultOffset; //represents the letter that best fits the english frequency values for a given column
            double maxCorrelation = 0.0; //represents the highest correleation value 
            
            // iterate through the english alphabet and for each letter calculate the correltaion value between the english frequency
            // and the frequency of the letter in the column using a shifting offset
            for (char shiftLetter = 'A'; shiftLetter <= 'Z'; shiftLetter++) {
                double correlation = 0.0; //represents the ccorrelation value of given letter
                
                // iterate through the englishFrequency dict and caluclate the measure of correlation between the letter frequency and english frequency
                for (Character letter : englishFrequency.keySet()) {
                    char shiftedLetter = (char)(((letter - defaultOffset) + (shiftLetter - defaultOffset)) % 26 + defaultOffset); //represents the shift of the given letter, for example move 3 letters forward
                    correlation += columnFrequency.get(shiftedLetter) * englishFrequency.get(letter); //summing of correlation of each letter
                }

                // find the shifted letter that best fits the current column by finding letter with the highest correlation
                if (correlation > maxCorrelation) { 
                    maxCorrelation = correlation; //set the max correlation 
                    bestFit = shiftLetter; //set the best fit letter that has the highest correlation
                }
            }
            cipherKey[i] = bestFit; //finally set the best fit letter that matches to the english frequency
        }
        return new String(cipherKey); //finally return the original cipher key that was used to encrypt the text
    }


    /************************************************************************************************
     * TASK 5: function that receives ciphertext, finds the correct cipher key used to encrypt the text and returns the original deciphered text
     */
    public static String DecryptCipherText(String cipherText) {
        char[] cipherTextArray = cipherText.toCharArray(); //convert the given ciphertext into char array for our operations
        String cipherKey = GetCipherKey(cipherTextArray); //call our function to find the original cipher key used to encryt the text
        String decipheredText = VigenereDecrypt(cipherText, cipherKey); //call our decryption function of Vigenere to get original text
        return decipheredText; //return original text before it was encrypted
    }



    /************************************************************************************************
     * This our main function for testing Vigenere breaking function
     */
    public static void main(String[] args) { 
        String plaintext = "DEFENDTHEEASTWALLOFTHECASTLE";
        String key = "FORTIFY";
        
        // TASK 1: checking the VigenereEncrypt and VigenereDecrypt functions
        System.out.println("Plain Text: " + plaintext + "\nKey: " + key + "\nEncrypting...\n");
        String ciphertext = Vigenere.VigenereEncrypt(plaintext, key);
        System.out.println("Cipher Text: " + ciphertext + "\nDecrypting...\n");
        String deciphered = Vigenere.VigenereDecrypt(ciphertext, key);
        System.out.println("Deciphered Text: " + deciphered + "\n");

        // TASK 2: checking the CreateFrequencyDict function
        Map<Character, Double> frequencyDict = Vigenere.CreateFrequencyDict(plaintext.toCharArray());
        System.out.println("Frequency Dict: " + frequencyDict + "\n");

        // Represents the given cipher text that we received to decipher
        ciphertext = "HUGVUKSATTMUNDKUMKVVAYVLPOMCEDTBGKIIEYARTREEDRINKFSMEMQNGFEHUVMAMHRUCPVVHBWMOGYZXVJWOMKBMAIELJVRPOMCEDRBWKIUNZEEEFRRPKMAZZYUDZRYRALVRZGNFLEKAKTVGNEJOAWBFLSEEBIAMSCIAKTVGNVRPKMAZHXDYXLNFIIIDJSEMPWJOHIIBZMKOMMZNAXVRZHGTWTZNBEGFFGYAHFRKKSFRJRYRALZSVRQGVXYIIKZHYIRHYMFMPRTTGCVKLQVMWIEBAARSDRGALFCEVOQXJIDBZVNGKIRCCWRIHVRTZHLBUKVMWIEPYSLGCXVMZKYONXHIVRKHZJYHVVVABIEEFMNINLRWALVMJVEHDZRIIPLBOEUSJYTAAXFBJVEHDJIOHQLUVSBSNYEVLEJEJJFNYVFWNSEKVAWOMXUXSSJTGIAHYIWOMXUXYEIEVRQKHHZAIXZTPHVNRLBFALVAIKREZRRMZPRGVVVNVQRELWJHZVRYVVVVZVZHYIRNYXUXZMCKZRFTKYECZVGTPRIUNXYBUKFFZEPAWYIPGIPNYXRIIXUKPPCEYQRYPPCEYQRPPXYFVRGTZXZCOIEKVVJNZZRKMICTWISHYIJOOLNMUSNTJWGBSPKHZFRTAMEGJJZROIRROMFMVSURZTRTAMEGOMFLVQVVDWVMVVVNOVRTAMEGZRGKHRTEVXZRJLRMWIEWVSISJQREHXVVDWVMVVVNOVRTAMEGZRGKHRTEVXZRJLRMWIEWVSITCMFBZMKAIHAHALZNBQBKLTIENIAMSCDYNSHENVVWNXEHUKVRCIFBAEKIIKGALREOGSAZLVJIMWNBKMFRHEQTTXIUGCLHBVWOMKVOLRVSNMVFWPFRZFHMALVFVGGBZMNANRNIWMEGVRQLVKVNOPLRVYTAHIETWTZNBEAWZSWADRGEFCFUXEZXAEGPDRTMHTGIIKNMTCTHVQOXYHFOMXUTAMJCVVPXDEJSPVRBOIRRYCBNOIIEDSCXUIUWDHRMOIUOJVQTYOEENWGALVVAIHAHALZNBQBKLHVEKMAMVXYEYEEDUIJSKIRKPRXLJRTBZXFOYXUXYINOIHRKPRXFZEEBUKUOPFGBUKURZEZBUKURZEZLUSDOMXNEZIMEMHNKLHKOYVRTTFVFJVRUBXKHZWVELRTEREFNUFIOFIATUHKHZWGBSPEENWTTCIEOOSXXUEEDOLRHUPPWJVQMOIIENTBDLRNANXUXDLZSKIEXKAFRYPRGVVVTCMFBDLZSKIEXKEEDVRRVOSDUMQHKLHSAXOGALAFRYPRGVVVMZVREFXYINEAWUSKHDRTFVVVBVGXBUXFTCIPAHQSEMXHKUMEGVPYFFWFUGAVMOMEMZFHKUMEGNSBGHKRIIMUXHVUAOECIPRXSJQRMOMEGGSHWLVKHVROXMSIENYEXSCJADHVLBVVLTXUTAMJSJQRMOMEGVXZRDMEDJAYTAXZCZPRMTIJEZXUXUAYAOXUXYIRTDWNGKXYINQLLAIIYZBCEVVVLZXZROIRROFRLAMCLVQBFLRKAIHGAPWDYNXRKFIOPGSEXAMJTCIJBUHRNYRBMOMEGHSEXVTVNCIEXPJCUIKGALWYUOXRKDLVNRMGATEEYVJYBYXRNYJYNAXVRDRGALVVSOICILHRSOEGXSCIAQIAHMXYENEVGAPPDVCFHMCFRZRBMALVLZEFMVFVINEAVLQRDZLRGVXRMDRHMLWKOKTRWVVJTVCRWOISUOAVMOQZEISSEVVUOMPNWFTVRXLRWHFFVZQLVOEDBZVQHVVGEMGUXKYGOIEONZXFFKEYEHWAUNXNUVZVMTGUTTFVRYSBKWIICCIQTUHJAOEAWUSKHDRTFVVVTCIAMOMJEWSARIMIDWITNPPZNBQLLHHWAIGLBUXFSHMYBUKSYOLRZYEMEVRQLAIINYIPHYYDOAXUXJSLNOIATUGVIOABKLXYOPKUMOCTRZWGULWYOMRNGKWYAQIAMOSLINEVWHVKSPVRGVGIAQIAZOEJTGCTKPQRNYEAVPIETMEIXUARNYIEBUKWRJQGALRZGCXYRZLFRZXRESQVWCEGMOICOMHYRUEDEDWBGALVNDKUMZTCUOSABHRJHJVRJBSKHOLRKHZVNIIIXYQFRZQHVOMDAMZRESIUTCMFNUKRIIPLYVACTJLRTYHZSXSHKZIJOKPNBUPPTCSHZOMKSVRFPLVCIOXYXTIRNDRTEPXKLZVRELZRNXCOHYIWOMARVHREOOLREWEXRZIVGNXYAORBEPZZNBLHFHRSEDRTXCIIYZXJTZFCENWRWDMKHNIRBUKSIMHNUVZVHDWPAHQSEMHBHYFZRYSEULEJTPTBGALVSXYYIAYIEYFHLAESOQIUBZGYAHFRKKSFRRMGAZYTHIEZXHWEEQIEFVVVBPXGALVRVZRFBAXZNBPBGLPPOIXUTATCAXMQUBWKSKSXXVRCYOLNMVRVWJVQTZMWHDWFHBPZNOLNMVRVWJVQALHZDJYGIVYINJXUBUKWUMXUXYXYEILRNAXVRZHAHAEWEVXUXYXYEILRYSYKTZVRWAMCLDWPTYGVLTQBKLXYAIQHMAIIEYSGALVWRDIAWZLRVZJYHDRSEASEXVRKHZQBKYSNHZAVESPVAQIZXHWDYCSCXZLRVZJYHDRSEASEXALVNOLRUPVUSVMQGLZVRHSEXZXRROPRWHXKHZWGBSPEENWOKVOVNWCEXWPPSJECMSCJPJORGKSLBOPRLZWRIYMJAHXZTPXGXYWZSDXFHUPPSOSPDHRUSOSEXJELGCXSKVQJOHIHGOEGPTQNLAIIWCSZNUQVRXMSNSHZSVWGXYJFLGSJXKJRSOEAWMSCLJARWMEJTZVGBSPYINWBGNWFNZFHKKIEBJVRMPPCTCIQBYKVSJJUBZLFPZXUTAQVLVRPAVPPBPVQXUFFRZSSGLZVRIIIXYQFRZFHMALVRVZRGZXZLGFRZBMCIIKNESQPFVRPRPRKONQVEPRXSOVNBNLKIRLRXSIUAXYFAPSEEYWRTAMEFMSAMVJSIMHNGKFLSOEAWKSFROLRGBTFNOLROLPMEOWVGRMEGDFRMVSBMTWREMXFLDRXBUKWAIGLNUXFFVRPRALZNFMAZDLRTOLVLVQZNJYFUPVUOACBKLAYAOXUBZKIIHYAZHMELTKUTZXCYBEHGAEEDJQVGVYJBDVQHMCFRZQRTUXZNXVBTRMEGIIIXYQFRZXUNZMJAOIAZHKVDDRTNLWJIIKONARFSTPYTIPVESTEXZWZNBXBMOIWORPJAVWVFDIERLCVSISJUBVEEYMAMVQPBJWBFZGFRZXUBZEEDHSEXPWRTYMIBUMEGRMGATCYEVHNMLEJEMIPEPRZNBSAMOITUNLVHUWMEGZRMSMEIIKGAHXKHZPNFWPZGCXTEVEKEYSRKIYKWCSFXCICVZXIBVPVTGMABUKNIOLGALPRMKPVZOXXLJEGBUKFEMWUXZLRLGTEXZWRHIIIXYQFRZXUXUQVTCSHZOXKHZEVKNVVWYIALLVGEMJHFLHWRJQNGBRJEZRPXUWVRNAHGNFPSZVNIOMDWCSFXMSFTAEYEZXZNFPRWVRKHZXHYAIUFGSBKDVVTXLVVYMVDOLLZVHYAOLYXUXKHZIORALVSZEAZLPJHZLNMOWVNOXUXLVVSKMGXYIJPDXRTUHEEKIAMOIWRJQGAFQVMJVVXZSWLZRBKLULAAJBJBEWFOLVLRMEDIICXUXYEVRQYVVXEOXUBZPFSOPRGVVVQPSGAALVRVZRGUIMEMQBKLTIOKLRMZEZDDXUBUKFFZZVEWVFPCIGLAMCLDJOBYHFRYIIBSAYEOLRKAIDPOIELLRKOMAUXALVROIZILWKTJWFXKXYEZLRKLEJHJVRWLWFLVXRRLXRLGYAWHYETZHBGALZSYIFXYXCAIHRGJLRNOIQHUXYINLBFLFPHJVEHYLRUIXRWAICLHIGKBPPIDQCEVVVINXUXYIZSOLRKLFRLHMAZPPVAYXRESQVTZPYFLMZMKPBKLULOOLGALVRVZRAXCIIMJVRIYSGHZXFTPHZTCMAZVJVVDPCKVTYEOWGBSPZFWMEWVVUEQMYUFXYAOLRTCIETCEGULRUSVFBOLYJBTXUTAKFDRIOHALRDJVRMLPCTCMFLVYCWDXULVVIORPNWLRZFRMGAPRKHZHVLAEETVMQXURZTNLNESGCANTNLHMETZHZTPHVNRLBFALVAIKREZRRMZPRGVVVCGEFIHVRRZEAWYEUIVRGFHMUEIAUHTXYEVRTXSWEAHIYXUSIELYBMOXYEMEIXURVVZVZHYISEOLNMDSIDJYELPKEOATNKAMEGWMEWVVWIZRQBZLIIZORWBTJTVVGBUKXEOXUXLFRCFMAMVXYEOIZILWKAIHGALRZGCXFISYKOIMNGZLFRZPRTCIEOWPNVRTCUHINLHXFKZRBYALRTGMRMOCJOPPUTALJPJORGSIRVZQLEVRVLDRRLZYEBMSXXUULIOXUXIYJTVFBOLQPDJSEMHOVTCCOXHOWRJQBNAQPHZEEMHRUTVORMOCWOMQSKVQFFAQLWVSIQPSGAALVRVZRGUIMEMQBKLEEDOLRKHZVNIIIXYJCIOXVGNWKIGPVLZMKTDRTLAMCLDWFBAXZNBSAMOIGAGPVWIYJTJJCTSPRSEYFMHFFVZQLVOEDBZVQHVVRNYLVLLCVSCEIXHPCTCIFXLQZNBSSTKIDOIWGAHXZSYVRTTMEGVRQMOICAHTYBNLKOZVUBTWKRZEZBUKKHMSJLALVSCEQHDSETCISEVSIAIHZRZSLLAVBFVYKTCEGLOEUORXUTAPZENJYHHXZNBSAMOIWLJSELOECLWIYBMXVDIIIXYQFRZ";
        
        // TASK 3: checking the GetKeyLength function
        int keyLength = Vigenere.GetKeyLength(ciphertext.toCharArray());
        System.out.println("Probable Key Length: " + keyLength + "\n");

        // TASK 4: checking the GetCipherKey function
        String cipherKey = Vigenere.GetCipherKey(ciphertext.toCharArray());
        System.out.println("Cipher Key: " + cipherKey + "\n");

        // TASK 5: checking the DecryptCipherText function
        String decryptedText = Vigenere.DecryptCipherText(ciphertext);
        System.out.println("Deciphered Text: " + decryptedText + "\n");
    }
}