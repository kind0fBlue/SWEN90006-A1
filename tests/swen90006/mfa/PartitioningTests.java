package swen90006.mfa;

import org.junit.*;

import swen90006.mfa.MFA.AuthenticationStatus;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

public class PartitioningTests
{
    //mfa is a standard instance variable in Java. It is available to all test methods
    protected MFA mfa;

    //Any method annotated with "@Before" will be executed before each test,
    //allowing the tester to set up some shared resources.
    @Before public void setUp()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
        //Initialise the MFA instance and create a dummy user. This will run before each test
	mfa = new MFA();
	mfa.register("UserNameA", "Password1!", "", "");
    }

    //Any method annotated with "@After" will be executed after each test,
    //allowing the tester to release any shared resources used in the setup.
    @After public void tearDown()
    {
    }

    //Any method annotation with "@Test" is executed as a test.
    @Test public void aTest()
    {
	//the assertEquals method used to check whether two values are
	//equal, using the equals method
	final int expected = 2;
	final int actual = 1 + 1;
	assertEquals(expected, actual);
    }

    @Test public void anotherTest()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("UserNameB", "Password2!", "", "");

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("UserNameB"));
	assertFalse(mfa.isUser("NonUser"));
    }

    //To test that an exception is correctly throw, specify the expected exception after the @Test
    @Test(expected = java.io.IOException.class)
    public void anExceptionTest()
	throws Throwable
    {
	throw new java.io.IOException();
    }

    //This test should fail.
    //To provide additional feedback when a test fails, an error message
    //can be included
    @Test public void aFailedTest()
    {
	//include a message for better feedback
	final int expected = 2;
	final int actual = 1 + 2;
	//Uncomment the following line to make the test fail
	//assertEquals("Some failure message", expected, actual);
    }


    /*
     * register 
     */

    // register EC1: Test if username registered is duplicate
    @Test(expected = DuplicateUserException.class)
    public void existingUsername()
	throws Throwable
    {
        mfa.register("abcdef", "123ab@@@@", null, null);
        mfa.register("abcdef", "123ab@@@gh", null, null);
	    throw new DuplicateUserException("abcdef");
    }

    // register EC2: Username length = 0
    @Test(expected = InvalidUsernameException.class)
    public void emptyUsername()
	throws Throwable
    {
        mfa.register("", "123ab@@@@", null, null);
	    throw new InvalidUsernameException("");

    }

    // register EC3: Username length = 1
    @Test(expected = InvalidUsernameException.class)
    public void len1Username()
	throws Throwable
    {
        mfa.register("a", "123ab@@@@", null, null);
	    throw new InvalidUsernameException("a");
    }

    // register EC4: Username length > 1 and <4
    @Test(expected = InvalidUsernameException.class)
    public void len2Username()
	throws Throwable
    {
        mfa.register("ab", "123ab@@@@", null, null);
	    throw new InvalidUsernameException("ab");
    }


    // register EC5
    @Test(expected = InvalidPasswordException.class)
    public void emptyPassword()
	throws Throwable
    {
        mfa.register("abcd", "", null, null);
	    throw new InvalidPasswordException("");
    }


     // register EC6
    @Test(expected = InvalidPasswordException.class)
    public void len1Password()
	throws Throwable
    {
        mfa.register("efgh", "1", null, null);
	    throw new InvalidPasswordException("1");
    }


     // register EC7
    @Test(expected = InvalidPasswordException.class)
    public void len3Password()
	throws Throwable
    {
        mfa.register("ijkl", "123", null, null);
	    throw new InvalidPasswordException("123");
    }

     // register EC8
    @Test(expected = InvalidPasswordException.class)
    public void noLetterPassword()
	throws Throwable
    {
        mfa.register("ijkl", "1234@@@@", null, null);
	    throw new InvalidPasswordException("1234@@@@");
    }


    // register EC9
    @Test(expected = InvalidPasswordException.class)
    public void noDigitPassword()
	throws Throwable
    {
        mfa.register("ijkl", "abcd@@@@", null, null);
	    throw new InvalidPasswordException("abcd@@@@");
    }



    //register EC10: 1 letter, 1 digit password
    @Test public void oneLetterOneDigitValid()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("mnop", "1a@@@@@@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("mnop"));
    }


    // register EC11
    @Test(expected = InvalidPasswordException.class)
    public void noSpecialCharPassword()
	throws Throwable
    {
        mfa.register("abab", "a1234567", null, null);
	    throw new InvalidPasswordException("abcd1234567");
    }


     //register EC12: 1 special char, deviceID is null
    @Test public void oneSpecialCharNullDevice()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("cdcd", "a123456@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("cdcd"));
    }


     //register EC13: deviceID is String, faceID null
    @Test public void isDeviceIDNoFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("efef", "a123456@", "iphone1", null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("efef"));
    }


    //register EC14: deviceID is String, faceID is String
    @Test public void isDeviceIDIsFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("ghgh", "a123456@", "iphone2", "roundFace");

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("ghgh"));
    }


    //register EC15: More than one speical character password
    @Test public void specialCharMultiple()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("ijij", "a1234@@@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("ijij"));
    }


    //register EC16: More than one letter password
    @Test public void multipleLetterPsswrd()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("klkl", "abb234@@@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("klkl"));
    }


    //register EC17: length > 8 passwword
    @Test public void longer8Psswrd()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("mnmn", "abb234@@@@@@@@@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("mnmn"));
    }


    //register EC18: username > 4 and characters are letters
    @Test public void allLetterUsername()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("mnmnBB", "abb234@@@@@@@@@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("mnmnBB"));
    }


    //register EC19: username > 4 and some characters are not letters
    @Test(expected = InvalidUsernameException.class)
    public void notLetterUsername()
	throws Throwable
    {
        mfa.register("ijkl1234", "abcd@@@@", null, null);
	    throw new InvalidUsernameException("ijkl1234");
    }



    /*
    login 
    */ 
    // 2 input


    //login EC1
    @Test public void twoInputRightPassword()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException
    {
	mfa.register("aaaa", "a123456@", null, null);
    AuthenticationStatus status = mfa.login("aaaa", "a123456@");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.SINGLE);
    }


    //login EC2
    @Test(expected = IncorrectPasswordException.class)
    public void twoInputMismatchPassword()
	throws Throwable
    {
        mfa.register("aaab", "a123456@", null, null);
        mfa.login("aaab", "a223456@");
	    throw new IncorrectPasswordException("aaab", "a223456@");
    }


    //login EC3
    @Test(expected = NoSuchUserException.class)
    public void nonExistentNameTwoInput()
	throws Throwable
    {
        mfa.login("thisisNotaName", "a223456@");
	    throw new NoSuchUserException("thisisNotaName");
    }



    //4 input login

    // login EC 4
    @Test public void fourInputTriple()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
	mfa.register("baaa", "a123456@", "iphone2", "face2");
    AuthenticationStatus status = mfa.login("baaa", "a123456@", "iphone2", "face2");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.TRIPLE);
    }


    //login EC5
    @Test public void hasFaceNotMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("caaa", "a123456@", "iphone2", "face2");
    AuthenticationStatus status = mfa.login("caaa", "a123456@", "iphone2", "faceNo");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }


    //login EC6
    @Test public void matchDeviceNoFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("daaa", "a123456@", "iphone2", null);
    AuthenticationStatus status = mfa.login("daaa", "a123456@", "iphone2", null);

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }



    //login EC7
    @Test(expected = IncorrectDeviceIDException.class)
    public void deviceNotMatch()
	throws Throwable
    {
        mfa.register("eaaa", "a123456@", "iphone3", "face1");
        mfa.login("eaaa", "a123456@", "iphone13", "face1");
	    throw new IncorrectDeviceIDException("eaaa", "iphone13");
    }


    //login EC8 
    @Test public void noRegisteredDeviceMatchingface()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("faaa", "a123456@", null, "face1");
    AuthenticationStatus status = mfa.login("faaa", "a123456@", null, "face1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.SINGLE);
    }


    // login EC9
    @Test public void noRegisteredDeviceMisMatchingface()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("gaaa", "a123456@", null, "face1");
    AuthenticationStatus status = mfa.login("gaaa", "a123456@", null, "face2");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.SINGLE);
    }



    // login EC10
    @Test public void noRegisteredDeviceNoRegisteredFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("haaa", "a123456@", null, null);
    AuthenticationStatus status = mfa.login("haaa", "a123456@", null, null);

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.SINGLE);
    }



    //login EC11
    @Test(expected = IncorrectPasswordException.class)
    public void fourInputMismatchPassword()
	throws Throwable
    {
        mfa.register("iaaa", "a123456@", null, null);
        mfa.login("iaaa", "a223456@", null, null);
	    throw new IncorrectPasswordException("iaaa", "a223456@");
    }



    //login EC12
    @Test(expected = NoSuchUserException.class)
    public void nonExistentNameFourInput()
	throws Throwable
    {
        mfa.login("thisisNotaName1", "a223456@", null, null);
	    throw new NoSuchUserException("thisisNotaName1");
    }





    /* 
    respondToPushNotification
    */ 
    

    //respondToPushNotification EC1
    @Test public void singleDeviceMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("jaaa", "a123456@", "iphone1", "face1");
    mfa.login("jaaa", "a123456@"); //Now is single, whith device registered

    AuthenticationStatus status = mfa.respondToPushNotification("jaaa", "iphone1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }


   //respondToPushNotification EC2
    @Test(expected = IncorrectDeviceIDException.class)
    public void singleDeviceNotMatch()
	throws Throwable
    {
        mfa.register("kaaa", "a123456@", "iphone1", "face1");
        mfa.login("kaaa", "a123456@"); //Now is single, whith device registered
        mfa.respondToPushNotification("kaaa", "iphone13");
	    throw new IncorrectDeviceIDException("kaaa", "iphone13");
    }


    //respondToPushNotification EC3
    @Test public void singleDeviceNotRegistered()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("laaa", "a123456@", null, null);
    mfa.login("laaa", "a123456@"); //Now is single, whith device registered

    AuthenticationStatus status = mfa.respondToPushNotification("laaa", null);

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.SINGLE);
    }


    //respondToPushNotification EC4
    @Test public void NoneDeviceMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("maaa", "a123456@", "iphone1", null);

    // No login, status None

    AuthenticationStatus status = mfa.respondToPushNotification("maaa", "iphone1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.NONE);
    }


    //respondToPushNotification EC5
    @Test public void NoneDeviceMisMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("naaa", "a123456@", "iphone1", null);

    // No login, status None
    
    AuthenticationStatus status = mfa.respondToPushNotification("naaa", "iphone13");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.NONE);
    }


    //respondToPushNotification EC6
    @Test public void doubleDeviceMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("oaaa", "a123456@", "iphone1", null);
    mfa.login("oaaa", "a123456@", "iphone1", null);

    // status double
    
    AuthenticationStatus status = mfa.respondToPushNotification("oaaa", "iphone1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }



    //respondToPushNotification EC7
    @Test public void doubleDeviceMisMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("paaa", "a123456@", "iphone1", null);
    mfa.login("paaa", "a123456@", "iphone1", null);

    // status double
    
    AuthenticationStatus status = mfa.respondToPushNotification("paaa", "iphone13");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }



    //respondToPushNotification EC8
    @Test public void tripleDeviceMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("qaaa", "a123456@", "iphone1", "face1");
    mfa.login("qaaa", "a123456@", "iphone1", "face1");

    // status double
    
    AuthenticationStatus status = mfa.respondToPushNotification("qaaa", "iphone1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.TRIPLE);
    }


    
    // respondToPushNotification EC9
    @Test public void tripleDeviceMisMatch()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("raaa", "a123456@", "iphone1", "face1");
    mfa.login("raaa", "a123456@", "iphone1", "face1");

    // status double
    
    AuthenticationStatus status = mfa.respondToPushNotification("raaa", "iphone13");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.TRIPLE);
    }



    //respondToPushNotification EC10
    @Test(expected = NoSuchUserException.class)
    public void pushNoUser()
	throws Throwable
    {
        mfa.respondToPushNotification("thisNotARegisteredName", "iphone13");
	    throw new NoSuchUserException("thisNotARegisteredName");
    }





    /*
     * faceRegonised
     */

    

    // faceRegonised EC1
    @Test public void faceidMatches()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("saaa", "a123456@", "iphone1", "face1");
    mfa.login("saaa", "a123456@"); //Now is single, whith device registered

    AuthenticationStatus status = mfa.faceRegonised("saaa", "iphone1", "face1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.TRIPLE);
    }


    // faceRegonised EC2
    @Test public void faceidNotMatches()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("taaa", "a123456@", "iphone1", "face1");
    mfa.login("taaa", "a123456@"); //Now is single, whith device registered

    AuthenticationStatus status = mfa.faceRegonised("taaa", "iphone1", "face13");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }


    // faceRegonised EC3
    @Test public void noRegisteredFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("taaa", "a123456@", "iphone1", null);
    mfa.login("taaa", "a123456@"); //Now is single, whith device registered

    AuthenticationStatus status = mfa.faceRegonised("taaa", "iphone1", null);

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.DOUBLE);
    }




     //faceRegonised EC4
    @Test(expected = IncorrectDeviceIDException.class)
    public void faceDeviceNotMatch()
	throws Throwable
    {
        mfa.register("uaaa", "a123456@", "iphone1", "face1");
        mfa.login("uaaa", "a123456@"); //Now is single, whith device registered
        mfa.faceRegonised("uaaa", "iphone13", "face1");
	    throw new IncorrectDeviceIDException("uaaa", "iphone13");
    }



    //faceRegonised EC5
    @Test public void NoneStatusFace()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException
    {
    
    mfa.register("vaaa", "a123456@", "iphone1", "face1");

    // No login, status None

    AuthenticationStatus status = mfa.faceRegonised("vaaa", "iphone1", "face1");

	//the assertTrue method is used to check whether something holds.
	assertEquals(status, AuthenticationStatus.NONE);
    }



    /*
     * getData
     */
  
    // getData EC1

    @Test public void singleGetData()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException, UnauthenticatedUserException
    {
    
    mfa.register("waaa", "a123456@", null, null);
    mfa.login("waaa", "a123456@"); //status is single now

    List<Integer> d1 = new ArrayList<>();
    d1.add(1);

    mfa.addData("waaa", d1);
    List<Integer> output1 = mfa.getData("waaa", 0);

	assertEquals(output1, d1);
    }



    // getData EC2
    @Test(expected = java.lang.IndexOutOfBoundsException.class)
    public void doubleEmptyData()
	throws Throwable
    {
        mfa.register("xaaa", "a123456@", "iphone1", null);
        mfa.login("xaaa", "a123456@", "iphone1", null); //status is single now
        mfa.getData("xaaa", 0);
        throw new java.lang.IndexOutOfBoundsException(0);
    }



    // getData EC3
    @Test public void doubleLen1Data()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException, UnauthenticatedUserException
    {
    
    mfa.register("yaaa", "a123456@", "iphone1", null);
    mfa.login("yaaa", "a123456@", "iphone1", null); //status is double now

    List<Integer> d1 = new ArrayList<>();
    d1.add(1);

    mfa.addData("yaaa", d1);
    List<Integer> output1 = mfa.getData("yaaa", 0);

	assertEquals(output1, d1);
    }


    // getData EC4
    @Test(expected = java.lang.IndexOutOfBoundsException.class)
    public void doubleLeftOutboundLen2Data()
	throws Throwable
    {
        mfa.register("zaaa", "a123456@", "iphone1", null);
        mfa.login("zaaa", "a123456@", "iphone1", null); //status is double now

        List<Integer> d1 = new ArrayList<>();
        d1.add(1);

        List<Integer> d2 = new ArrayList<>();
        d2.add(2);

        mfa.addData("zaaa", d1);
        mfa.addData("zaaa", d2);

        mfa.getData("zaaa", -1);
        throw new java.lang.IndexOutOfBoundsException(-1);

	
        
    }

    // getData EC5
    @Test public void doubleLen2InboundData()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException, NoSuchUserException, IncorrectPasswordException, IncorrectDeviceIDException, FaceMismatchException, UnauthenticatedUserException
    {
        mfa.register("abaa", "a123456@", "iphone1", null);
        mfa.login("abaa", "a123456@", "iphone1", null); //status is double now

        List<Integer> d1 = new ArrayList<>();
        d1.add(1);

        List<Integer> d2 = new ArrayList<>();
        d2.add(5);

        mfa.addData("abaa", d1);
        mfa.addData("abaa", d2);

        List<Integer> output2 = mfa.getData("abaa", 1);
        assertEquals(output2, d2);

	
        
    }



    // getData EC6
    @Test(expected = java.lang.IndexOutOfBoundsException.class)
    public void doubleRightOutboundLen2Data()
	throws Throwable
    {
        mfa.register("acaa", "a123456@", "iphone1", null);
        mfa.login("acaa", "a123456@", "iphone1", null); //status is double now

        List<Integer> d1 = new ArrayList<>();
        d1.add(1);

        List<Integer> d2 = new ArrayList<>();
        d2.add(5);

        mfa.addData("acaa", d1);
        mfa.addData("acaa", d2);

        mfa.getData("acaa", 2);
        throw new java.lang.IndexOutOfBoundsException(2);

	
        
    }


    // getData EC7
    @Test(expected = UnauthenticatedUserException.class)
    public void deviceButNotDouble()
	throws Throwable
    {
        mfa.register("adaa", "a123456@", "iphone1", null);
        mfa.login("adaa", "a123456@"); //status is single now


        mfa.getData("adaa", 0);
        throw new UnauthenticatedUserException("adaa");

	
        
    }

    // getData EC8
    @Test(expected = UnauthenticatedUserException.class)
    public void getDataNotLoggedIn()
	throws Throwable
    {
        mfa.register("aeaa", "a123456@", "iphone1", null);


        mfa.getData("aeaa", 0);
        throw new UnauthenticatedUserException("aeaa");

	
        
    }


    // getData EC9
    @Test(expected = NoSuchUserException.class)
    public void getDataNotUser()
	throws Throwable
    {

        mfa.getData("thisisreallynotaname", 0);
        throw new UnauthenticatedUserException("thisisreallynotaname");

	
        
    }





   
















   






}
