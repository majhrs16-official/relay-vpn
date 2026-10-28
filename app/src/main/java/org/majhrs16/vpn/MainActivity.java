package org.majhrs16.vpn;

import org.majhrs16.vpn.R;
import org.majhrs16.vpn.data.Config;
import org.majhrs16.vpn.service.VPNService;
import org.majhrs16.vpn.shared.NodeLog;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

	private static final String TAG = "MainActivity";
	private EditText editPsk, editServerPort, editNodeIp, editServerHost, editServerPortNode;
	private TextView logView;
	private ScrollView logScroll;

	private final ActivityResultLauncher<Intent> vpnPermissionLauncher = registerForActivityResult(
			new ActivityResultContracts.StartActivityForResult(),
			result -> {
				if (result.getResultCode() == RESULT_OK) {
					Toast.makeText(this, "Permiso de VPN concedido", Toast.LENGTH_SHORT).show();
					startVpnService();
				} else {
					Toast.makeText(this, "Permiso de VPN denegado", Toast.LENGTH_LONG).show();
					NodeLog.w(TAG, "El usuario rechazó el diálogo de permisos de VPN.");
				}
			}
	);

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		editPsk = findViewById(R.id.editPsk);
		editServerPort = findViewById(R.id.editLhPort);
		editNodeIp = findViewById(R.id.editNodeIp);
		editServerHost = findViewById(R.id.editNodeLhHost);
		editServerPortNode = findViewById(R.id.editNodeLhPort);

		Button btnSave = findViewById(R.id.btnSave);
		Button btnStartNode = findViewById(R.id.btnStartNode);
		Button btnStopNode = findViewById(R.id.btnStopNode);
		logView = findViewById(R.id.logView);
		logScroll = findViewById(R.id.logScroll);
		Button btnClearLogs = findViewById(R.id.btnClearLogs);

		loadUIConfig();
		btnClearLogs.setOnClickListener(v -> NodeLog.clear());
		NodeLog.i(TAG, "Interfaz lista. Relay y logs activos.");

		btnSave.setOnClickListener(v -> {
			saveUIConfig();
			NodeLog.i(TAG, "Configuración guardada.");
		});

		btnStartNode.setOnClickListener(v -> {
			saveUIConfig();
			NodeLog.i(TAG, "Solicitando inicio de la VPN...");
			Intent intent = VpnService.prepare(this);
			if (intent != null) {
				vpnPermissionLauncher.launch(intent);
			} else {
				startVpnService();
			}
		});

		btnStopNode.setOnClickListener(v -> {
			NodeLog.i(TAG, "Deteniendo la VPN...");
			Intent intent = new Intent(this, VPNService.class);
			intent.setAction("ACTION_STOP_VPN");
			startService(intent);
		});
	}

	private void refreshLogs() {
		logView.setText(NodeLog.getText());
		logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
	}

	@Override
	protected void onStart() {
		super.onStart();
		NodeLog.setListener(() -> runOnUiThread(() -> refreshLogs()));
		refreshLogs();
	}

	@Override
	protected void onStop() {
		NodeLog.setListener(null);
		super.onStop();
	}

	private void loadUIConfig() {
		Config config = Config.load(this);
		editPsk.setText(config.psk);
		editServerPort.setText(String.valueOf(config.serverPort));
		editNodeIp.setText(config.nodeVirtualIp);
		editServerHost.setText(config.serverHost);
		editServerPortNode.setText(String.valueOf(config.serverPortNode));
	}

	private void saveUIConfig() {
		Config config = new Config();
		config.psk = editPsk.getText().toString();
		config.nodeVirtualIp = editNodeIp.getText().toString();
		config.serverHost = editServerHost.getText().toString();
		try {
			config.serverPort = Integer.parseInt(editServerPort.getText().toString());
			config.serverPortNode = Integer.parseInt(editServerPortNode.getText().toString());
		} catch (Exception e) {}
		config.save(this);
	}

	private void startVpnService() {
		Intent intent = new Intent(this, VPNService.class);
		intent.setAction("ACTION_START_VPN");
		startForegroundService(intent);
	}
}
