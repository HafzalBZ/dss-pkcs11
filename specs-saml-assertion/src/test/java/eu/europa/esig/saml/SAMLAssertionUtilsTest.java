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
package eu.europa.esig.saml;

import eu.europa.esig.saml.jaxb.assertion.AssertionType;
import eu.europa.esig.saml.jaxb.metadata.EntityDescriptorType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SAMLAssertionUtilsTest {

	private static SAMLAssertionUtils samlAssertionUtils;

	@BeforeAll
	static void init() {
		samlAssertionUtils = SAMLAssertionUtils.getInstance();
	}

	@SuppressWarnings("unchecked")
	@Test
	void test() throws JAXBException, SAXException {
		JAXBContext jc = samlAssertionUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = samlAssertionUtils.getSchema();
		assertNotNull(schema);

		File file = new File("src/test/resources/sample-saml-assertion.xml");

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<AssertionType> unmarshalled = (JAXBElement<AssertionType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);
	}

	@SuppressWarnings("unchecked")
	@Test
	void metadata () throws JAXBException {

		JAXBContext jc = samlAssertionUtils.getJAXBContext();

		File file = new File("src/test/resources/Metadata.xml");
		Unmarshaller unmarshaller = jc.createUnmarshaller();

		JAXBElement<EntityDescriptorType> unmarshalled = (JAXBElement<EntityDescriptorType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);

		file = new File("src/test/resources/ServiceMetadata.xml");
		unmarshalled = (JAXBElement<EntityDescriptorType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);
	}

}
