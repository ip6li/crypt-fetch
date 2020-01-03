class MyX509 extends window.cfcrypt.X509 {

    constructor(name, doRestoreConfig) {
        super(name, doRestoreConfig);
    }

    loadConfig(configURL) {
        return super.loadConfig(configURL);
    }

    login(credentials) {
        return super.login(credentials).then((data)=>{
            return data;
        });
    }

    cryptFetch (message) {
        return super.cryptFetch(message).then((data)=>{
            return data;
        });
    }
}


window.cfcrypt.MyX509 = MyX509;
