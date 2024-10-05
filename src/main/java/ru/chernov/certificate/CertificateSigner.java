package ru.chernov.certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMParser;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateSigner {

    public static void main(String[] args) {
        try {
            // Загрузите корневой сертификат и закрытый ключ
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(Files.newInputStream(Paths.get("C:\\Program Files\\Java\\jre-1.8\\bin\\rootCA.jks")), "ciscoenjoyer".toCharArray());

            PrivateKey rootKey = (PrivateKey) keyStore.getKey("rootCA", "ciscoenjoyer228".toCharArray());
            X509Certificate rootCert = (X509Certificate) keyStore.getCertificate("rootCA");

            // Загрузите CSR
            PKCS10CertificationRequest csr = loadCSR("C:\\Program Files\\Java\\jre-1.8\\bin\\service.csr");

            // Получите SubjectPublicKeyInfo из CSR
            SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

            // Преобразуйте SubjectPublicKeyInfo в PublicKey
            PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(subjectPublicKeyInfo);

            // Подпишите CSR
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    rootCert.getSubjectX500Principal(),
                    BigInteger.valueOf(System.currentTimeMillis()), // Серийный номер
                    new Date(System.currentTimeMillis()), // Дата начала действия
                    new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L)), // Дата окончания действия
                    new X500Principal(csr.getSubject().toString()), // Субъект из CSR
                    publicKey // Открытый ключ из CSR
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(rootKey);
            X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

            // Сохраните подписанный сертификат в файл
            try (FileOutputStream fos = new FileOutputStream("signedService.crt")) {
                fos.write(signedCert.getEncoded());
            }

            System.out.println("Сертификат успешно подписан!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PKCS10CertificationRequest loadCSR(String csrFilePath) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(csrFilePath))) {
            return (PKCS10CertificationRequest) pemParser.readObject();
        }
    }
}

