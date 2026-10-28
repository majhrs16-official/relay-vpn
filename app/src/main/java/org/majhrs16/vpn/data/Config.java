package org.majhrs16.vpn.data;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

public class Config {
	private static final String FILENAME = "config.properties";

	public String psk = "";

	public String nodeVirtualIp = "10.42.0.1";
	public int nodePrefix = 24;
	public int serverPortNode = 4242;

	public String serverHost = "0.0.0.0";
	public int serverPort = 4242;

	public static Config load(Context context) {
		Config config = new Config();
		File configFile = new File(context.getFilesDir(), FILENAME);

		if (!configFile.exists()) {
			config.save(context);
			return config;
		}

		Properties prop = new Properties();
		try (InputStream input = new FileInputStream(configFile)) {
			prop.load(input);
			config.psk = prop.getProperty("security.psk", "");

			config.nodeVirtualIp = prop.getProperty("node.virtual_ip", "10.42.0.1");
			config.nodePrefix = Integer.parseInt(prop.getProperty("node.prefix", "24"));
			config.serverPortNode = Integer.parseInt(prop.getProperty("node.server_port", "4242"));

			config.serverHost = prop.getProperty("node.server_host", "0.0.0.0");
			config.serverPort = Integer.parseInt(prop.getProperty("server.port", "4242"));
		} catch (Exception e) {}

		return config;
	}

	public void save(Context context) {
		File configFile = new File(context.getFilesDir(), FILENAME);
		Properties prop = new Properties();

		prop.setProperty("server.port", String.valueOf(this.serverPort));
		prop.setProperty("security.psk", this.psk);
		prop.setProperty("node.virtual_ip", this.nodeVirtualIp);
		prop.setProperty("node.prefix", String.valueOf(this.nodePrefix));
		prop.setProperty("node.server_host", this.serverHost);
		prop.setProperty("node.server_port", String.valueOf(this.serverPortNode));

		try (OutputStream output = new FileOutputStream(configFile)) {
			prop.store(output, "VPN tunnel configuration");
		} catch (Exception e) {}
	}
}
