package com.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import net.sf.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

public class SignatureAndVerify {
	private static String url, secretId, timestamp, nonce, sign_string,
			signature;
	private static List<String> image_url = new ArrayList<String>();
	private static List<File> image_file = new ArrayList<File>();

	public static void main(String[] args) {
		SignatureAndVerify sv = new SignatureAndVerify();

		secretId = "你的secretId";
		timestamp = Math.round(System.currentTimeMillis() / 1000.0) + "";
		nonce = Math.random() + "";
		sign_string = secretId + "," + timestamp + "," + nonce;
		url = "http://api.open.tuputech.com/v3/recognition/" + secretId;

		// 如果采用传递URL的方式
		image_url
				.add("http://img.my.csdn.net/uploads/201302/01/1359697713_5224.png");
		image_url
				.add("http://i.mmcdn.cn/simba/img/TB1Z465HFXXXXceXVXXSutbFXXX.jpg");
		// 如果采用直接post文件的方式
		// image_file.add(new File("img/aa.jpg"));
		// image_file.add(new File("img/bb.jpg"));

		// 得到签名
		signature = sv.Signature(sign_string);
		String result = sv.upload();
		if(!result.equals("err")){
			JSONObject jsonObject = JSONObject.fromObject(result);
			String result_json = jsonObject.getString("json");
			String result_signature = jsonObject.getString("signature");
			// 进行验证
			boolean verify = sv.Verify(result_signature, result_json);
			if (verify) {
				System.out.println("验证成功：" + result_json);
			} else {
				System.out.println("验证失败：");
			}
		}
	}

	/**
	 * 进行签名
	 * 
	 * @param sign_string
	 *            参与签名的文本
	 * 
	 **/
	private String Signature(String sign_string) {
		try {
			// 读取你的密钥pkcs8_private_key.pem
			File private_key_pem = new File("pem/pkcs8_private_key.pem");
			InputStream inPrivate = new FileInputStream(private_key_pem);
			String privateKeyStr = readKey(inPrivate);
			byte[] buffer = Base64.decode(privateKeyStr);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			// 获取密钥对象
			PrivateKey privateKey = (RSAPrivateKey) keyFactory
					.generatePrivate(keySpec);

			// 用私钥对信息生成数字签名
			Signature signer = Signature.getInstance("SHA256WithRSA");
			signer.initSign(privateKey);
			signer.update(sign_string.getBytes());
			byte[] signed = signer.sign();
			return new String(Base64.encode(signed));
		} catch (Exception e) {
			return "err";
		}
	}

	/**
	 * 进行验证
	 * 
	 * @param signature
	 *            数字签名
	 * @param json
	 *            真正的有效数据的字符串
	 * 
	 **/
	public boolean Verify(String signature, String json) {
		try {
			// 读取图普公钥open_tuputech_com_public_key.pem
			File open_tuputech_com_public_key_pem = new File(
					"pem/open_tuputech_com_public_key.pem");
			InputStream inPublic = new FileInputStream(
					open_tuputech_com_public_key_pem);
			String publicKeyStr = readKey(inPublic);
			byte[] buffer = Base64.decode(publicKeyStr);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
			// 获取公钥匙对象
			PublicKey pubKey = (RSAPublicKey) keyFactory
					.generatePublic(keySpec);

			Signature signer = Signature.getInstance("SHA256WithRSA");
			signer.initVerify(pubKey);
			signer.update(json.getBytes());
			// 验证签名是否正常
			return signer.verify(Base64.decode(signature));
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * 读取密钥信息
	 * 
	 * @param in
	 * @throws IOException
	 */
	private String readKey(InputStream in) throws IOException {
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String readLine = null;
		StringBuilder sb = new StringBuilder();
		while ((readLine = br.readLine()) != null) {
			if (readLine.charAt(0) == '-') {
				continue;
			} else {
				sb.append(readLine);
				sb.append('\r');
			}
		}
		return sb.toString();
	}

	// 采用HttpClient进行post
	public String upload() {
		try {
			HttpClient client = new DefaultHttpClient();// 开启一个客户端 HTTP 请求
			HttpClientParams.setCookiePolicy(client.getParams(),
					CookiePolicy.BROWSER_COMPATIBILITY);
			HttpPost httpPost = new HttpPost(url);// 创建 HTTP POST 请求
			MultipartEntityBuilder builder = MultipartEntityBuilder.create();
			ContentType contentType = ContentType.create(HTTP.PLAIN_TEXT_TYPE,
					HTTP.UTF_8);
			// 设置为浏览器兼容模式
			builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
			// 设置请求的编码格式
			builder.setCharset(Charset.forName(HTTP.UTF_8));
			// 如果采用传递URL的方式，则将url添加至参数中
			if (image_url.size() > 0) {
				for (int i = 0; i < image_url.size(); i++) {
					builder.addPart("image", new StringBody(image_url.get(i),
							contentType));
				}
				// 如果采用直接post文件的方式，则将file文件添加至参数中
			} else if (image_file.size() > 0) {
				for (int i = 0; i < image_file.size(); i++) {
					if (image_file.get(i).exists()) {
						ContentBody cbFile = new FileBody(image_file.get(i));
						builder.addPart("image", cbFile);
					}

				}
			}

			builder.addPart("timestamp", new StringBody(timestamp, contentType));
			builder.addPart("nonce", new StringBody(nonce, contentType));
			builder.addPart("signature", new StringBody(signature, contentType));

			HttpEntity entity = builder.build();// 生成 HTTP POST 实体
			httpPost.setEntity(entity);// 设置请求参数
			HttpResponse response = client.execute(httpPost);// 发起请求 并返回请求的响应

			String result = EntityUtils.toString(response.getEntity(),HTTP.UTF_8);
			return result;
		} catch (Exception e) {
			System.out.println(e.toString());
			return "err";
		}
	}
}
