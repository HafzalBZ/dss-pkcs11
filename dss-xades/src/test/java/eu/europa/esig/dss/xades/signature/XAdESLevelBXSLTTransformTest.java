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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XsltTransform;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

class XAdESLevelBXSLTTransformTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample-with-different-id.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		List<DSSReference> references = new ArrayList<>();
		
		DSSReference dssReference = new DSSReference();
		dssReference.setId("DSS-REF-1");
		dssReference.setUri("");
		dssReference.setContents(documentToSign);
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
		
		Document xsltTemplate = DomUtils.buildDOM("<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
				+ "<xsl:template match=\"/\">" 
				+ "<xsl:apply-templates select=\"//*[@Id='hello']\" />"
				+ "</xsl:template>"
				+ "</xsl:stylesheet>");
		
		DSSTransform xPathTransform = new XsltTransform(xsltTemplate);
		dssReference.setTransforms(Arrays.asList(xPathTransform));
		references.add(dssReference);

		signatureParameters.setReferences(references);

		service = new XAdESService(getOfflineCertificateVerifier());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// the reference output does not equal to the original file content
		// do nothing
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
