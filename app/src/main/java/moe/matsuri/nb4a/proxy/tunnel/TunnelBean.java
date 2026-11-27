package moe.matsuri.nb4a.proxy.tunnel;

import androidx.annotation.NonNull;
import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;
import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

/** Embedded transports. The wire format is versioned independently of Room. */
public class TunnelBean extends AbstractBean {
    public static final int DNSCAT2 = 0;
    public static final int SSHUTTLE = 1;
    public int kind;
    public String domain;
    public String secret;
    public String recordTypes;
    public int delay = 1000;
    public String username;
    public String password;
    public String privateKey;
    public String privateKeyPassphrase;
    public String hostKey;
    public String python;

    @Override
    public void initializeDefaultValues() {
        if (serverPort == null) serverPort = kind == SSHUTTLE ? 22 : 53;
        super.initializeDefaultValues();
        if (domain == null) domain = "";
        if (secret == null) secret = "";
        if (recordTypes == null) recordTypes = "TXT";
        if (username == null) username = "";
        if (password == null) password = "";
        if (privateKey == null) privateKey = "";
        if (privateKeyPassphrase == null) privateKeyPassphrase = "";
        if (hostKey == null) hostKey = "";
        if (python == null) python = "python3";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(0);
        super.serialize(output);
        output.writeInt(kind);
        output.writeString(domain);
        output.writeString(secret);
        output.writeString(recordTypes);
        output.writeInt(delay);
        output.writeString(username);
        output.writeString(password);
        output.writeString(privateKey);
        output.writeString(privateKeyPassphrase);
        output.writeString(hostKey);
        output.writeString(python);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        if (version != 0) throw new IllegalArgumentException("Unknown tunnel profile version");
        super.deserialize(input);
        kind = input.readInt();
        domain = input.readString();
        secret = input.readString();
        recordTypes = input.readString();
        delay = input.readInt();
        username = input.readString();
        password = input.readString();
        privateKey = input.readString();
        privateKeyPassphrase = input.readString();
        hostKey = input.readString();
        python = input.readString();
    }

    @Override public boolean canTCPing() { return kind == SSHUTTLE; }
    @Override public boolean canICMPing() { return false; }
    @Override public boolean canMapping() { return false; }
    @Override public String network() { return "tcp"; }
    @NonNull @Override public String toString() {
        return "TunnelBean{kind=" + kind + ", credentials=<redacted>}";
    }

    @NonNull
    @Override
    public TunnelBean clone() {
        return KryoConverters.deserialize(new TunnelBean(), KryoConverters.serialize(this));
    }

    public static final Creator<TunnelBean> CREATOR = new CREATOR<TunnelBean>() {
        @NonNull @Override public TunnelBean newInstance() { return new TunnelBean(); }
        @Override public TunnelBean[] newArray(int size) { return new TunnelBean[size]; }
    };
}
