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

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;

class JAdESMultipleDocumentDetachedWithObjectByUriTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private JAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;
	private JAdESService jadesService;

	@BeforeEach
	void init() throws Exception {
		documentToSigns = Arrays.asList(new FileDocument("src/test/resources/sample.json"),
				new FileDocument("src/test/resources/sample.png"),
				new InMemoryDocument("Hello World!".getBytes(), "helloWorld"));
		
		jadesService = new JAdESService(getOfflineCertificateVerifier());

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return documentToSigns;
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return jadesService;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

}
