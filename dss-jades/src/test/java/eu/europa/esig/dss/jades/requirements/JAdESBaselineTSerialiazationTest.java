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
package eu.europa.esig.dss.jades.requirements;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNull;

class JAdESBaselineTSerialiazationTest extends AbstractJAdESSerializationSignatureRequirementsCheck {

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
		return signatureParameters;
	}
	
	@Override
	protected void checkCertificateValues(Map<?, ?> unprotectedHeaderMap) {
		List<?> xVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "xVals");
		assertNull(xVals);
		
		List<?> axVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "axVals");
		assertNull(axVals);
	}
	
	@Override
	protected void checkRevocationValues(Map<?, ?> unprotectedHeaderMap) {
		List<?> rVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "rVals");
		assertNull(rVals);
		
		List<?> arVals = (List<?>) getEtsiUElement(unprotectedHeaderMap, "arVals");
		assertNull(arVals);
	}
	
	@Override
	protected void checkArchiveTimestamp(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> arcTst = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "arcTst");
		assertNull(arcTst);
	}

	@Override
	protected void checkTstValidationData(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> tstVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "tstVD");
		assertNull(tstVD);
	}

	@Override
	protected void checkAnyValidationData(Map<?, ?> unprotectedHeaderMap) {
		Map<?, ?> anyVD = (Map<?, ?>) getEtsiUElement(unprotectedHeaderMap, "anyValData");
		assertNull(anyVD);
	}

}
