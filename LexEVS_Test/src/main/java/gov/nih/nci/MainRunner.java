/**
 * National Cancer Institute Center for Bioinformatics
 *
 * LexEVS_Test_42
 * gov.nih.nci
 * MainRunner.java
 * Aug 18, 2009
 *
 */
/** <!-- LICENSE_TEXT_START -->
 The LexEVS_Test_42 Copyright 2009 Science Applications International Corporation (SAIC)
 Copyright Notice.  The software subject to this notice and license includes both human readable source code form and machine readable, binary, object code form (the EVSAPI Software).  The EVSAPI Software was developed in conjunction with the National Cancer Institute (NCI) by NCI employees and employees of SAIC.  To the extent government employees are authors, any rights in such works shall be subject to Title 17 of the United States Code, section 105.
 This LexEVS_Test_42 Software License (the License) is between NCI and You.  You (or Your) shall mean a person or an entity, and all other entities that control, are controlled by, or are under common control with the entity.  Control for purposes of this definition means (i) the direct or indirect power to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.
 This License is granted provided that You agree to the conditions described below.  NCI grants You a non-exclusive, worldwide, perpetual, fully-paid-up, no-charge, irrevocable, transferable and royalty-free right and license in its rights in the LexEVS_Test_42 Software to (i) use, install, access, operate, execute, copy, modify, translate, market, publicly display, publicly perform, and prepare derivative works of the EVSAPI Software; (ii) distribute and have distributed to and by third parties the EVSAPI Software and any modifications and derivative works thereof; and (iii) sublicense the foregoing rights set out in (i) and (ii) to third parties, including the right to license such rights to further third parties.  For sake of clarity, and not by way of limitation, NCI shall have no right of accounting or right of payment from You or Your sublicensees for the rights granted under this License.  This License is granted at no charge to You.
 1.	Your redistributions of the source code for the Software must retain the above copyright notice, this list of conditions and the disclaimer and limitation of liability of Article 6, below.  Your redistributions in object code form must reproduce the above copyright notice, this list of conditions and the disclaimer of Article 6 in the documentation and/or other materials provided with the distribution, if any.
 2.	Your end-user documentation included with the redistribution, if any, must include the following acknowledgment: This product includes software developed by SAIC and the National Cancer Institute.  If You do not include such end-user documentation, You shall include this acknowledgment in the Software itself, wherever such third-party acknowledgments normally appear.
 3.	You may not use the names "The National Cancer Institute", "NCI" Science Applications International Corporation and "SAIC" to endorse or promote products derived from this Software.  This License does not authorize You to use any trademarks, service marks, trade names, logos or product names of either NCI or SAIC, except as required to comply with the terms of this License.
 4.	For sake of clarity, and not by way of limitation, You may incorporate this Software into Your proprietary programs and into any third party proprietary programs.  However, if You incorporate the Software into third party proprietary programs, You agree that You are solely responsible for obtaining any permission from such third parties required to incorporate the Software into such third party proprietary programs and for informing Your sublicensees, including without limitation Your end-users, of their obligation to secure any required permissions from such third parties before incorporating the Software into such third party proprietary software programs.  In the event that You fail to obtain such permissions, You agree to indemnify NCI for any claims against NCI by such third parties, except to the extent prohibited by law, resulting from Your failure to obtain such permissions.
 5.	For sake of clarity, and not by way of limitation, You may add Your own copyright statement to Your modifications and to the derivative works, and You may provide additional or different license terms and conditions in Your sublicenses of modifications of the Software, or any derivative works of the Software as a whole, provided Your use, reproduction, and distribution of the Work otherwise complies with the conditions stated in this License.
 6.	THIS SOFTWARE IS PROVIDED "AS IS," AND ANY EXPRESSED OR IMPLIED WARRANTIES, (INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE) ARE DISCLAIMED.  IN NO EVENT SHALL THE NATIONAL CANCER INSTITUTE, SAIC, OR THEIR AFFILIATES BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * <!-- LICENSE_TEXT_END -->
 */
package gov.nih.nci;

import gov.nih.nci.cadsr.testCoreTypeQueries;
import gov.nih.nci.evs.testCTS2;
import gov.nih.nci.evs.testDataIntegrity;
//import gov.nih.nci.cadsr.testCoreTypeQueries;
import gov.nih.nci.ncicb.cadsr.evs.testSIW;

/**
 * @author safrant
 *
 */
public class MainRunner {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String address = "";
		String cts2Address = "";
		String configFilesLocation = "";
		testDataIntegrity tdi;
		boolean doAdvanced = false;

		if (args.length > 0) {
			for (int i = 0; i < args.length; i++) {
				String option = args[i];
				// if (option.equalsIgnoreCase("--help")) {
				// printHelp();
				// }
				if (option.equalsIgnoreCase("-I")) {
					address = args[++i];
				}
				if (option.equalsIgnoreCase("-C")) {
					cts2Address = args[++i];
				}
				if (option.equalsIgnoreCase("-L")) {
					configFilesLocation = args[++i];
				}
				if (option.equalsIgnoreCase("-V")) {
					doAdvanced = true;
				}
			}
		}

		try {
			if (doAdvanced) {

				if (address.length() > 0) {
					new testCoreTypeQueries(address);
				}

				if (address.length() > 0) {
					new testSIW(address);
				}
			}

			if (address.length() > 0) {
				tdi = new testDataIntegrity(address, configFilesLocation);
			} else {
				tdi = new testDataIntegrity(configFilesLocation);
			}
			tdi.findConceptsByCode();
			tdi.findByPreferredName();
			tdi.testListCodingSchemes();
			tdi.testVersion();
			tdi.testCodingSchemeSearchability();
			tdi.testName_and_Synonym();
			tdi.testSupportedProperties();
			tdi.testHistory();
			tdi.testCodingSchemeMetadata();
			tdi.getBySource();
			tdi.testQuickSearch();
			if (configFilesLocation.length() > 1) {
				tdi.testLocalNames(configFilesLocation + "LocalNames.txt");
			}
			tdi.testHierarchy();
			tdi.testSearchDoubleMetaphone();

			// Value sets
			tdi.testListValueSets();
			if (doAdvanced) {
				tdi.CacheValueSetDefinition_NCIt();
				tdi.cacheValeSetDefinition_NDFRT();
				tdi.testSearchValueSetForTerm();
			}

			testCTS2 cts2 = new testCTS2(cts2Address);
			cts2.doTests();

		}
		// logger.debug("Testing log4j");}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void printHelp() {
		System.out.println("");
		System.out.println("Usage: MainRunner [OPTIONS]");
		System.out.println(" ");
		System.out.println("  -I, \t\tPath to the lexbig tier to be tested)");
		System.out.println("  -L, \tPath to the config directory");
		System.out.println("  -V, \t\tInclude if doing local advanced testing. Exclude if doing data release testing");
		System.exit(1);
	}

	// private static Logger logger = Logger.getLogger(MainRunner.class);
}
