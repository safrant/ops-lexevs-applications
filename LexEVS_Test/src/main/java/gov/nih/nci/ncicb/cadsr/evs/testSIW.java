package gov.nih.nci.ncicb.cadsr.evs;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;





public class testSIW {

	private Logger logger = Logger.getLogger(testSIW.class.getName());
	
	public testSIW(String address) {
		// TODO Auto-generated constructor stub
		this.vocabName = "NCI_Thesaurus";
		findByConceptCode("C12434", false);
		findByPreferredName("Sex",true);
		findBySynonym("Blue", true);
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
	
	  private static LexEVSQueryService evsService = new LexEVSQueryServiceImpl();

	  private String vocabName = null;


	  
	  public void findByConceptCode(String code, boolean includeRetired) 
	  {
	    try {
	    	System.out.println("Test findByConceptCode");
	    	
	      List<EVSConcept> evsConcepts = (List<EVSConcept>)evsService.findConceptsByCode(code, includeRetired, 100, vocabName);
	      
	      for(EVSConcept evsConcept : evsConcepts) {
	         System.out.println(evsConcept.getCode());
	      }
	    } catch (Exception e){
	      logger.warn(e.getMessage());
	    } // end of try-catch
	    

	  }
	  
	  public void findByPreferredName(String s, boolean includeRetired) 
	  {


	    try {
	    	System.out.println("Test findByPreferredName");
	      List<EVSConcept> evsConcepts = evsService.findConceptsByPreferredName(s, includeRetired, vocabName);
	      
	      for(EVSConcept evsConcept : evsConcepts) {
	    	  System.out.println(evsConcept.getCode());
	      }
	    } catch (Exception e){
	      e.printStackTrace();
	    } // end of try-catch

	
	  }

	  public void findBySynonym(String s, boolean includeRetired) 
	  {
	    s = s.replace('%','*');



	    try {
	    	System.out.println("Test findBySynonym");
	      List<EVSConcept> evsConcepts = evsService.findConceptsBySynonym(s, includeRetired, 100, vocabName);
	      
	      for(EVSConcept evsConcept : evsConcepts) {
	    	  System.out.println(evsConcept.getCode());
	      }
	    } catch (Exception e){
	      e.printStackTrace();
	    } // end of try-catch


	  }
	

}
