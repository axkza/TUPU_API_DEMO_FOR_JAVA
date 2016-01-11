package com.test;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

public class APIDemo {
	private static String secretId = "你的secretID";
	private static String url = "http://api.open.tuputech.com/v3/recognition/" + secretId;
	private static List<String> image_url = new ArrayList<String>();
	private static List<File> image_file = new ArrayList<File>();

	public static void main(String[] args) {
		APIDemo sv = new APIDemo();
		CloseableHttpClient httpClient = sv.initHttpClient();

		// 如果采用传递URL的方式
		image_url.add("http://img.my.csdn.net/uploads/201302/01/1359697713_5224.png");
		image_url.add("http://i.mmcdn.cn/simba/img/TB1Z465HFXXXXceXVXXSutbFXXX.jpg");
		// 如果采用直接post文件的方式
		// image_file.add(new File("img/aa.jpg"));
		// image_file.add(new File("img/bb.jpg"));

		String timestamp = Math.round(System.currentTimeMillis() / 1000.0) + "";
		String nonce = Math.random() + "";
		String sign_string = secretId + "," + timestamp + "," + nonce;
		// 得到签名
		String signature = SignatureAndVerify.Signature(sign_string);

		String result = sv.upload(httpClient, timestamp, nonce, signature);

		if (!result.equals("err")) {
			JSONObject jsonObject = JSONObject.fromObject(result);
			String result_json = jsonObject.getString("json");
			String result_signature = jsonObject.getString("signature");
			// 进行验证
			boolean verify = SignatureAndVerify.Verify(result_signature,
					result_json);
			if (verify) {
				System.out.println("验证成功：" + result_json);
			} else {
				System.out.println("验证失败：" + result_json);
			}
		}
	}
	
	/**
	 * 实例一个全局HttpClient
	 * 
	 **/
	public CloseableHttpClient initHttpClient() {
		// 设置请求和传输超时时间
		RequestConfig requestConfig = RequestConfig.custom()
				.setSocketTimeout(50000).setConnectTimeout(50000).build();
		PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
		HttpHost localhost = new HttpHost(url);
		// 将最大连接数增加到200
		cm.setMaxTotal(200);
		// 将每个路由基础的连接增加到20
		cm.setDefaultMaxPerRoute(20);
		// 将目标主机的最大连接数增加到50
		cm.setMaxPerRoute(new HttpRoute(localhost), 50);

		CloseableHttpClient httpClient = HttpClients.custom()
				.setConnectionManager(cm)
				.setDefaultRequestConfig(requestConfig).build();
		return httpClient;
	}
	
	/**
	 * 采用HttpClient进行post
	 * 
	 * @param httpClient HttpClient实例
	 * @param timestamp 时间戳
	 * @param nonce 随机数
	 * @param signature 签名
	 * 
	 **/
	public String upload(CloseableHttpClient httpClient, String timestamp,
			String nonce, String signature) {
		MultipartEntityBuilder builder = MultipartEntityBuilder.create();
		HttpPost httpPost = new HttpPost(url);// 创建 HTTP POST 请求
		try {
			ContentType contentType = ContentType.create(HTTP.PLAIN_TEXT_TYPE,
					HTTP.UTF_8);
			builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
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
			CloseableHttpResponse response = httpClient.execute(httpPost);// 发起请求

			String result = EntityUtils.toString(response.getEntity(),
					HTTP.UTF_8);
			response.close();
			return result;
		} catch (Exception e) {
			System.out.println(e.toString());
			return "err";
		} finally {
			httpPost.releaseConnection();
			httpPost.abort();
		}
	}
}
