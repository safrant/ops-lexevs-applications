package gov.nih.nci.cadsr.common;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class StringUtil {

	private static final Logger logger = Logger.getLogger(StringUtil.class
			.getName());
	private static Pattern idSequencePattern = Pattern
			.compile("^[A-Za-z0-9_-]{36}$");
	protected static final Pattern publicIdPattern = Pattern.compile("^[0-9]+$");
	private static Pattern searchParameterTypePattern = Pattern
			.compile("^[a-zA-Z\\s]*$");
	private static Pattern versionPattern = Pattern
			.compile("^[a-zA-Z0-9',_\\s\\/\\-\\$\\*\\.\\(\\)]*$");
	
	public static final String CHANGE_NOTE_SEPARATOR = "; ";
	public static final int MAX_CHANGE_NOTE_IN_BYTES = 2000;
	
	public static String trimDoubleQuotes(String value) throws Exception {
		boolean temp = false;

		if (value == null)
			throw new Exception("value is NULL or empty!");

		value = value.trim();

		if (value.indexOf("\"") == 0) {
			value = value.substring(1, value.length());
		}
		if (value.lastIndexOf("\"") == value.length() - 1) {
			value = value.substring(0, value.length() - 1);
		}

		return value;
	}

	public static String handleNull(String value) {
		String retVal = "";

		if (value != null) {
			retVal = value;
		}

		return retVal;
	}

	public static int handleNumber(String value) {
		int retVal = -1;

		if (value != null && !"".equals(value.trim())) {
			try {
				retVal = Integer.valueOf(value).intValue();
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
		}

		return retVal;
	}

	public static Long handleLongNumber(String value) {
		Long retVal = -1L;

		if (value != null && !"".equals(value.trim())) {
			try {
				retVal = Long.valueOf(value).longValue();
			} catch (NumberFormatException e) {
				e.printStackTrace();
			}
		}

		return retVal;
	}

	public static boolean handleYesNo(String value) {
		boolean retVal = false;

		if (value != null && "true".equalsIgnoreCase(value))
			retVal = true;

		return retVal;
	}

	public static boolean isNumber(String numberStr) {
		boolean retVal = true;

		try {
			Long n = Long.getLong(numberStr);
		} catch (Exception e) {
			retVal = false;
		}

		return retVal;
	}

	/*
	 * Escape special characters and trim any trailing spaces as well Source:
	 * http://www.javapractices.com/topic/TopicAction.do?Id=96
	 */
	public static String safeString(String str) throws Exception {
		final StringBuilder result = new StringBuilder();
		final StringCharacterIterator iterator = new StringCharacterIterator(
				str);
		char character = iterator.current();
		boolean found = false;
		while (character != CharacterIterator.DONE) {
			if ((int) character < 32 || (int) character > 126) {
				result.append(" "); // JR1024 just ignore it instead of
									// converting to whitespace; rolled back due
									// to breaking changes for totally new PV
									// without any VM
				found = true;
				// System.out.println("Ctrl char detected -"+(int)character+"-, filtered with a space!");
			} else {
				result.append(character);
			}
			character = iterator.next();
		}
		if (found) {
			logger.debug("Ctrl char detected in the original string [" + str
					+ "] xstring [" + toASCIICode(str) + "] filtered string ["
					+ result + "]");
		}
		return result.toString(); // JR1024 trim extra spaces, if any; rolled
									// back due to breaking changes for totally
									// new PV without any VM
	}

	/** "xray" function - prints out its ASCII value */
	public static String toASCIICode(String str) throws Exception {
		final StringBuilder result = new StringBuilder();
		final StringCharacterIterator iterator = new StringCharacterIterator(
				str);
		char character = iterator.current();
		while (character != CharacterIterator.DONE) {
			if ((int) character < 32 || (int) character > 126) {
				result.append("{").append((int) character).append("}");
			} else {
				result.append(character);
			}
			character = iterator.next();
		}
		return result.toString();
	}

	/**
	 * Source: http://www.kodejava.org/examples/237.html
	 */
	public static String toString(Throwable e) {
		// Create a StringWriter and a PrintWriter both of these object
		// will be used to convert the data in the stack trace to a string.
		//
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);

		//
		// Instead of writting the stack trace in the console we write it
		// to the PrintWriter, to get the stack trace message we then call
		// the toString() method of StringWriter.
		//
		e.printStackTrace(pw);

		return sw.toString();
	}

	public static long countWords(String text, String delimiter)
			throws Exception {
		if (text == null || delimiter == null) {
			throw new Exception("Text or delimiter can not be NULL or empty.");
		}
		return Arrays.asList(text.split(delimiter)).size();
	}

	/**
	 * This method is added to address XSS issue discovered during app scan.
	 * This method returns a string which removed HTML constructs. It also escapes HTML Basic characters:
	 * '<', '>', '"', '&' become &lt; &gt; &quot, &amp;
	 * We need to make sure we do not double escape a string by calling 'escapeHtmlEncodedValue' after calling this method.
	 *
	 * @param stringToClean
	 * @return
	 */
	public static String cleanJavascriptAndHtml(String stringToClean) {
		if (stringToClean == null)
			return stringToClean;
//		stringToClean = stringToClean.replaceAll("alert\\(", "(");
//		stringToClean = stringToClean.replaceAll("<script", "<");
//		stringToClean = stringToClean.replaceAll("</script", "</");
//		stringToClean = stringToClean.replaceAll("javascript", "");
//		stringToClean = stringToClean.replaceAll(".html", "");
//		stringToClean = stringToClean.replaceAll("iframe", "");
//		stringToClean = stringToClean.replaceAll("UTL_HTTP.REQUEST", "");

		//JR1107
		stringToClean = sanitizeHTML(stringToClean);
		stringToClean = escapeHtmlEncodedValue(stringToClean);
		return stringToClean;
	}

	protected static String sanitizeHTML(String untrustedHTML) {
        String ret = resolveHex( untrustedHTML );

		try {
			if(untrustedHTML != null) {
				PolicyFactory policy = new HtmlPolicyBuilder().toFactory();;
				ret = policy.sanitize(untrustedHTML);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		//we want to remove HTML and partial HTML escape because this method does not escape all the charactres we need to
		ret = unescapeHtmlEncodedValue(ret);
		return ret;
	}

    public static String[] sanitizeHTML( String[] untrustedHTML )
    {
        if( untrustedHTML == null)
        {
            return null;
        }
        String ret[] = new String[untrustedHTML.length];
        PolicyFactory policy = Sanitizers.FORMATTING.and( Sanitizers.LINKS );
        for( int f = 0; f < untrustedHTML.length; f++ )
        {
            try
            {
                if( untrustedHTML != null )
                {
                    ret[f] = policy.sanitize( resolveHex(untrustedHTML[f] ));
                }
            } catch( Exception e )
            {
                e.printStackTrace();
            }
        }
        return ret;
    }

	public static String[] cleanJavascriptAndHtmlArray(String[] stringToClean) {
		if (stringToClean != null && stringToClean.length > 0) {
			for (int i = 0; i < stringToClean.length; i++) {
				stringToClean[i] = cleanJavascriptAndHtml(stringToClean[i]);
			}
		}
		return stringToClean;
	}

	/**
	 * Validate the ID sequence
	 *
	 * @param idSequenceToCheck
	 * @return
	 */
	public static boolean validateElementIdSequence(String idSequenceToCheck) {
		return validatePatternAndValue(idSequencePattern, idSequenceToCheck);
	}

	/**
	 * Validate the search parameter type
	 *
	 * @param parameterTypeToCheck
	 * @return
	 */
	public static boolean validateSearchParameterType(
			String parameterTypeToCheck) {
		return validatePatternAndValue(searchParameterTypePattern,
				parameterTypeToCheck);
	}

	/**
	 * Validate the Public Id of a CDE Element
	 *
	 * @param publicIdToCheck
	 * @return
	 */
	public static boolean validateElementPublicId(String publicIdToCheck) {
		return validatePatternAndValue(publicIdPattern, publicIdToCheck);
	}
	public static boolean validateVersion(String versionToCheck) {
		return validatePatternAndValue(versionPattern, versionToCheck);
	}

	protected static boolean validatePatternAndValue(Pattern checkPattern,
			String valueToCheck) {
		if (StringUtils.isEmpty(valueToCheck))
			return true;//we do not fail an empty values validation
		try {
			String htmlUnescaped = unescapeHtmlEncodedValue(valueToCheck);
			return checkPattern.matcher(htmlUnescaped).matches();
		} catch (Exception e) {
			logger.error("validatePatternAndValue exception on valueToCheck: " + valueToCheck + ", " + e);
			e.printStackTrace();
		}
		return false;
	}

    public static String resolveHex( String s )
    {
        // Match percent sign followed by 2 characters zero through nine and/or a through f.
        String regex = "%[0-9a-fA-F]{2}";
        Pattern pattern = Pattern.compile( regex );
        Matcher matcher = pattern.matcher( s );
        while( matcher.find() )
        {
            String hex = s.substring(  matcher.start(), matcher.end() );
            hex = hex.replaceFirst( "^%", "" );
            s = s.replace( "%"+hex, Character.toString( (char)Integer.parseInt(hex, 16)) );
            matcher =  pattern.matcher( s );
        }
        return  s;
    }


    public static String convertHexToString( String hex )
    {

        StringBuilder sb = new StringBuilder();
        for( int i = 0; i < hex.length() - 1; i += 2 )
        {

            //grab the hex in pairs
            String output = hex.substring( i, ( i + 2 ) );
            //convert hex to decimal
            int decimal = Integer.parseInt( output, 16 );
            //convert the decimal to character
            sb.append( ( char ) decimal );
        }
        return sb.toString();
    }

	/**
	 *  Return false if s contains > or < or %
	 *  This used to catch attempts to sneak JavaScript, HTML, or  into server call parameters.
	 * @param s string to be checked
	 * @return
	 */
	public static boolean isHtmlAndScriptClean( String s)
	{
		if( s.matches( "^.*(%|<|>).*$" ))
		{
			return false;
		}
        return true;
	}

	public static boolean isHtmlAndScriptClean( List<String> s)
	{
		for( String str: s )
		{
			if( ! isHtmlAndScriptClean(s) )
			{
				return false;
			}
		}
		return true;
	}

   public static boolean isValidParmeter(HttpServletRequest req, String parameter )
   {
       boolean isValid = true;
       if( (StringUtils.isNotEmpty(parameter)) && ( req.getParameter( parameter ) != null ) && ( !StringUtil.isHtmlAndScriptClean( req.getParameter( parameter ) ) ) )
       {
           logger.error( "Bad value for " + parameter + " [" + req.getParameter( parameter ) + "]" );
           isValid = false;
       }
        return isValid;
   }
   public static boolean isValidListParmeter(Collection<String> vList, String parameterValue )
   {
       if ((StringUtils.isNotEmpty(parameterValue)) && (vList != null)) {
    	   return vList.contains(parameterValue);
       }
       else {
    	   return true;
       }
   }
   public static String decodeNumericChars(String str) {
	   if (! StringUtils.isEmpty(str)) {
	       StringBuffer sb = new StringBuffer();
	       int i1=0;
	       int i2=0;

	       while(i2<str.length()) {
	          i1 = str.indexOf("&#",i2);
	          if (i1 == -1 ) {
	               sb.append(str.substring(i2));
	               break ;
	          }
	          sb.append(str.substring(i2, i1));
	          i2 = str.indexOf(";", i1);
	          if (i2 == -1 ) {
	               sb.append(str.substring(i1));
	               break ;
	          }

	          String tok = str.substring(i1+2, i2);
	           try {
	                int radix = 10 ;
	                if (tok.charAt(0) == 'x' || tok.charAt(0) == 'X') {
	                   radix = 16 ;
	                   tok = tok.substring(1);
	                }
	                sb.append((char) Integer.parseInt(tok, radix));
	           } catch (NumberFormatException exp) {
	        	   logger.error("decodeNumericChars str = " + str, exp);
	                sb.append(str.substring(i1, i2+1));
	           }
	           i2++ ;
	       }
	       return sb.toString();
	   }
	   else
		   return str;
   }
   public static String unescapeHtmlEncodedValue(String paramValue) {
		String unescapedStr = StringEscapeUtils.unescapeHtml4(paramValue);
		return unescapedStr;

		//If we decided to simplify special characters we need to add the next call:
		//return simplifySpecialChars(unescapedStr);

		//all calls for the method 'unescapeHtmlEncodedValue' shall follow by changing corresponding Bean fields with HTML-escaped new values
		//the code to add will be like this:
		//String sLongName = StringUtil.unescapeHtmlEncodedValue(vd.getVD_LONG_NAME());
        //if (! StringUtils.equals(sLongName, vd.getVD_LONG_NAME())) {
        //	vd.setVD_LONG_NAME(StringUtil.escapeHtmlEncodedValue(sLongName));
        //}
   }
   /**
    * This function returns HMTL escaped value.
    * 
    * @param paramValue
    * @return
    */
   public static String escapeHtmlEncodedValue(String paramValue) {
	   String decodeNumeric = decodeNumericChars(paramValue);
	   //let's try to prevent double encoding if a string was partly escaped
	   String sourceUnescaped = StringEscapeUtils.unescapeHtml4(decodeNumeric);
	   return StringEscapeUtils.escapeHtml4(sourceUnescaped);
   }
   /**
    * This code is currently not used.
    *
    * @param source
    * @return String with simplified characters
    */
   public static String simplifySpecialChars(String source) {
		StringBuilder sb = new StringBuilder();
		if (StringUtils.isNotEmpty(source)) {
			char[] sourceChars = new char[source.length()];
			source.getChars(0, source.length(), sourceChars, 0);
			for (char curr : sourceChars) {
				switch (curr) {
				case 8800 : sb.append("<>"); break;
				case 8804 : sb.append("<="); break;
				case 8805 : sb.append(">="); break;
				case 8223 : sb.append("\""); break;
				default: sb.append(curr);
				}
			}
		}
		return sb.toString();
   }
   public static String escapeForJavascriptEncodedValue(String paramValue) {
	   if (StringUtils.isEmpty(paramValue)) 
		   return null;
	   String escaped = org.apache.commons.lang.StringEscapeUtils.escapeJavaScript(paramValue);
	   //clean up wrongly escaped tabs and new lines
	   escaped = escaped.replaceAll("\\\\n", "\n").replaceAll("\\\\t", "\t");
	   return escaped;
   }
   /**
    * Builds a new String with a restricted amount of bytes.
    * Uses default platform encoding.
    * 
    * @param strToBytes source String
    * @param maxBytes int how many bytes is allowed to use
    * @return String with no more than maxBytes
    */
   public static String truncate2GivenLengthInBytes(String strToBytes, int maxBytes) {
       //CURATNTOOL-1271 required this method not to exceed allowed DB column length on string concatenation
       return truncate2GivenLengthInBytes(strToBytes, maxBytes, Charset.defaultCharset());
   }
   /**
    * Builds a new String with a restricted amount of bytes.
    * 
    * @param strToBytes source String
    * @param maxBytes int how many bytes is allowed to use
    * @param charsetCurr what String encoding to use or null for platform default
    * @return String with no more than maxBytes
    */
   public static String truncate2GivenLengthInBytes(final String strToBytes, int maxBytes, final Charset charsetCurr) {
       if ((StringUtils.isEmpty(strToBytes)) || (maxBytes < 0)) {
           return strToBytes;
       }

       Charset charset = (charsetCurr == null) ? Charset.defaultCharset() : charsetCurr;

       CharsetDecoder decoder = charset.newDecoder();
       byte[] sba = strToBytes.getBytes(charset);
       if (sba.length <= maxBytes) {
           return strToBytes;
       }
       //byte buffer to maxBytes
       ByteBuffer bb = ByteBuffer.wrap(sba, 0, maxBytes);
       CharBuffer cb = CharBuffer.allocate(maxBytes);
       //Ignore an incomplete character
       decoder.onMalformedInput(CodingErrorAction.IGNORE);
       decoder.decode(bb, cb, true);
       decoder.flush(cb);
       String res = new String(cb.array(), 0, cb.position());
       return res;
   }
   /**
    * Concatenates change note for BE operation.
    * 
    * @param changeNote - a new change note
    * @param oldChangeNote - an old change note
    * @return String - merged change note truncate to allowed column length. If a new change note is empty returns the old note.
    */
   //CURATNTOOL-1271
   public static String mergeChangeNotes(final String changeNote, final String oldChangeNote) {
	   if (StringUtils.isEmpty(changeNote)) {
		   return oldChangeNote;
	   }
	   String result;
	   if (StringUtils.isEmpty(oldChangeNote)) {
		   result = changeNote;
	   }
	   else {
		   result = changeNote + CHANGE_NOTE_SEPARATOR + oldChangeNote;
	   }
	   result = StringUtil.truncate2GivenLengthInBytes(result, MAX_CHANGE_NOTE_IN_BYTES);
	   return result;
   }
}
