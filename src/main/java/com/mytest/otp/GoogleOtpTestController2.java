//되는 소스
package com.mytest.otp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Handles requests for the application home page.
 */
@Controller
@RequestMapping("/googleOtp2")
public class GoogleOtpTestController2 {
	
	private static final Logger logger = LoggerFactory.getLogger(GoogleOtpTestController2.class);
	
	
	/**
	 * 로그인 입력창
	 * @throws ServletRequestBindingException 
	 */
	@RequestMapping(value = {"/", "first"})
	public String first(HttpServletRequest request, Model model) throws ServletRequestBindingException {
		
		String result = ServletRequestUtils.getStringParameter(request, "result","");
		model.addAttribute("result", result );
		
		return "googleotp/first";
	}
	
	final String test_id = "admin";
	final String test_pw = "1111";
	
	/**
	 * id/pw 비교 및 성공인 경우 google otp 생성 후 입력창 리턴
	 * @param request
	 * @param locale
	 * @param model
	 * @return
	 * @throws ServletRequestBindingException 
	 */
	@RequestMapping(value = "/second")
	public String second(HttpServletRequest request, Locale locale, Model model) throws ServletRequestBindingException {
		
		String id= ServletRequestUtils.getStringParameter(request, "user_id");
		String pw= ServletRequestUtils.getStringParameter(request, "user_pw");
		
		if(id.equals(test_id) && pw.equals(test_pw))
		{
			String secretKeyStr = "GXRZIYSI";// 매번 생성하지 않고 한번 생성된 키를 사용.
			//String secretKeyStr = generateSecretKey();// 매번 생성
			String url = getQRBarcodeURL("kw191211", "testEmail.com", secretKeyStr); // 생성된 바코드 주소!
	        // userName과 hostName은 변수로 받아서 넣어야 하지만, 여기선 테스트를 위해 하드코딩 해줬다.
	        System.out.println("URL : " + url);
	        
			model.addAttribute("secretKey", secretKeyStr);
			model.addAttribute("url", url);
			//otp 생성
			return "googleotp/second";
		}
		else
		{
			return "redirect:first?result=fail";
		}
		
		
	}
	
	
	/**
	 * @param locale
	 * @param model
	 * @return
	 */
	@RequestMapping(value = "/third")
	public String select(HttpServletRequest req, Model model) {
		
		String user_codeStr = req.getParameter("user_code");
        long user_code = Integer.parseInt(user_codeStr);
        String encodedKey = req.getParameter("secretKey");
        long l = new Date().getTime();
        long ll =  l / 30000;
         
        boolean check_code = false;
        try {
            // 키, 코드, 시간으로 일회용 비밀번호가 맞는지 일치 여부 확인.
            check_code = check_code(encodedKey, user_code, ll);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        if(check_code){
        	return "googleotp/third";
        }else{
        	return "redirect:first?result=fail_otp";
        }
        
        
	}
	
	private String generateSecretKey(){
		
		// Allocating the buffer
//      byte[] buffer = new byte[secretSize + numOfScratchCodes * scratchCodeSize];
        byte[] buffer = new byte[5 + 5 * 5];
         
        // Filling the buffer with random numbers.
        // Notice: you want to reuse the same random generator
        // while generating larger random number sequences.
        new Random().nextBytes(buffer);
 
        // Getting the key and converting it to Base32
        Base32 codec = new Base32();
//      byte[] secretKey = Arrays.copyOf(buffer, secretSize);
        byte[] secretKey = Arrays.copyOf(buffer, 5);
        byte[] bEncodedKey = codec.encode(secretKey);
         
        // 생성된 Key!
        String encodedKey = new String(bEncodedKey);
         
        System.out.println("encodedKey : " + encodedKey);
        
        
        return encodedKey;
	}
	
	public static String getQRBarcodeURL(String user, String host, String secret) {
        String format = "http://chart.apis.google.com/chart?cht=qr&amp;chs=300x300&amp;chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&amp;chld=H|0";
         
        return String.format(format, user, host, secret);
    }
	
	private static boolean check_code(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
 
        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.
        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyGoogleOtp(decodedKey, t + i);
 
            if (hash == code) {
                return true;
            }
        }
 
        // The validation code is invalid.
        return false;
    }
	
	
	private static int verifyGoogleOtp(byte[] key, long t)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
 
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);
 
        int offset = hash[20 - 1] & 0xF;
 
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
 
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
 
        return (int) truncatedHash;
    }
}
