package swen90006.mfa;

public class FaceMismatchException extends Exception{
	
	public FaceMismatchException(boolean status) {
		super("Face Matches "+ status);
	}

}
