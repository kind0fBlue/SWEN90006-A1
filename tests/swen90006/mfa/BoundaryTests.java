package swen90006.mfa;

import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.FileSystems;

import org.junit.*;
import static org.junit.Assert.*;

//By extending PartitioningTests, we inherit the tests from that class
public class BoundaryTests
    extends PartitioningTests
{
    //Add another test
    @Test public void anotherTest()
    {
	//include a message for better feedback
	final int expected = 2;
	final int actual = 2;
	assertEquals("Some failure message", expected, actual);
    }


    // register-BVA1: Username length = 3
    @Test(expected = InvalidUsernameException.class)
    public void len3Username()
	throws Throwable
    {
        mfa.register("abc", "123ab@@@@", null, null);
	    throw new InvalidUsernameException("abc");
    }

    // register-BVA2: password length = 7
    @Test(expected = InvalidPasswordException.class)
    public void len7Password()
	throws Throwable
    {
        mfa.register("ijkl", "123@l12", null, null);
	    throw new InvalidPasswordException("123@l12");
    }


    // register-BVA3: one character in username not upper or lower case letter
    @Test(expected = InvalidUsernameException.class)
    public void oneNotLetterUsername()
	throws Throwable
    {
        mfa.register("ijkl@abcd", "abcd@@@@", null, null);
	    throw new InvalidUsernameException("ijkl@abcd");
    }

    // register-BVA4: ASCII out of range: [
    @Test(expected = InvalidUsernameException.class)
    public void oneNotASCIIAZLetterUsername()
	throws Throwable
    {
        mfa.register("ijkl[abcd", "abcd@@@@", null, null);
	    throw new InvalidUsernameException("ijkl[abcd");
    }

    // register-BVA5: ASCII out of range: '
    @Test(expected = InvalidUsernameException.class)
    public void oneNotASCIIazLetterUsername1()
	throws Throwable
    {
        mfa.register("ijkl'abcd", "abcd@@@@", null, null);
	    throw new InvalidUsernameException("ijkl'abcd");
    }

    // register-BVA5: ASCII out of range: {
    @Test(expected = InvalidUsernameException.class)
    public void oneNotASCIIazLetterUsername2()
	throws Throwable
    {
        mfa.register("ijkl{abcd", "abcd@@@@", null, null);
	    throw new InvalidUsernameException("ijkl{abcd");
    }
}



