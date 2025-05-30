/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class JAdESLevelLTCounterSignatureExtensionTest extends AbstractJAdESCounterSignatureTest {

    private JAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    private String signingAlias;

    private JAdESSignatureParameters signatureParameters;
    private JAdESCounterSignatureParameters counterSignatureParameters;
    private JAdESSignatureParameters extensionParameters;

    private ValidationDataEncapsulationStrategy vdStrategy;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < ValidationDataEncapsulationStrategy.values().length; i++) {
            args.add(Arguments.of(ValidationDataEncapsulationStrategy.values()[i]));
        }
        return args.stream();
    }

    @BeforeEach
    void init() throws Exception {

        signingAlias = RSASSA_PSS_GOOD_USER;

        signedDocument = new FileDocument(new File("src/test/resources/sample.json"));
        signingDate = new Date();

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        signingAlias = RSA_SHA3_USER;

        counterSignatureParameters = new JAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
        counterSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        extensionParameters = new JAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        extensionParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        // init certVerifier and revocation sources after PKI creation
        service = new JAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = RSASSA_PSS_GOOD_USER;
        return super.sign();
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        service.setTspSource(getGoodTsaCrossCertification());
        signingAlias = RSA_SHA3_USER;
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatureId);

        service.setTspSource(getGoodTsa());
        DSSDocument extendedDocument = service.extendDocument(counterSigned, extensionParameters);

        signingAlias = RSASSA_PSS_GOOD_USER;
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);

        return extendedDocument;
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @ParameterizedTest(name = "JAdES Level LT with Counter Signature Extension {index} : {0}")
    @MethodSource("data")
    void test(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        vdStrategy = validationDataEncapsulationStrategy;
        extensionParameters.setValidationDataEncapsulationStrategy(vdStrategy);
        super.signAndVerify();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(1, signatures.size());

        AdvancedSignature signature = signatures.iterator().next();
        assertEquals(1, signature.getCounterSignatures().size());
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        switch (vdStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertEquals(12, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                assertEquals(6, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(6, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertEquals(6, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(2, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(4, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertEquals(6, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(6, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(12, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            default:
                fail(String.format("The strategy '%s' is not supported!", vdStrategy));
        }
    }

    @Override
    protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        switch (vdStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertEquals(4, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(4, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            default:
                fail(String.format("The strategy '%s' is not supported!", vdStrategy));
        }
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip (different signers)
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
