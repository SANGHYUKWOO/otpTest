package com.myapp.otp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
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

import com.mytest.otp.GoogleOtpApp;

/**
 * Handles requests for the application home page.
 */
@Controller
@RequestMapping("/googleOtp")
public class GoogleOtpTestController {
	
	private static final Logger logger = LoggerFactory.getLogger(GoogleOtpTestController.class);
	
	GoogleOtpApp googleOtpApp = new GoogleOtpApp();
	
	
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
	@SuppressWarnings("unchecked")
	@RequestMapping(value = "/second")
	public String second(HttpServletRequest request, Locale locale, Model model) throws ServletRequestBindingException {
		
		String id= ServletRequestUtils.getStringParameter(request, "user_id");
		String pw= ServletRequestUtils.getStringParameter(request, "user_pw");
		String email= ServletRequestUtils.getStringParameter(request, "email");
		String user = email.split("@")[0];
		String host = email.split("@")[1];
		System.out.println("user :"+user+"     host : "+host);
		
		//return googleOTPAuth(model, id, pw, user, host);
		if(matchID(id,pw))
		{
			//model = googleOTPAuth(model, id, pw, user, host);
			HashMap<String, String> map = (HashMap<String, String>) googleOtpApp.googleOTPAuth(id, pw, user, host);
			model.addAttribute("secretKey", map.get("secretKey"));
			model.addAttribute("url", map.get("url"));
			return "googleotp/second";
		} else {
			return "redirect:first?result=fail";
		}
	}
	


	@RequestMapping(value = "/otpLogin")
	public String otpLogin(HttpServletRequest req, Model model) {
		if(googleOtpApp.select(req)){
        	return "googleotp/third";
        }else{
        	return "redirect:first?result=fail_otp";
        }
	}

	//사용자 로그인 ID PW 검증
	private boolean matchID(String id, String pw) {
		return id.equals(test_id) && pw.equals(test_pw);
	}
}
