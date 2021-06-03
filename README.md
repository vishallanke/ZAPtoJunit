# ZAPtoJunit

[WIP] Summary
This repository converts ZAP Security Test JSON report to JUnit XML file. After this conversion, you can use https://github.com/vishallanke/ReportPortalCypressJUnitAgent to send test execution results to report portal

You will be able to add exception and generate whitelist JSON file. Out of Scope security testing results will be removed from main security testing report.

This plugins also generates ZAP JUNIT XML file in which Defect Severity is at parent level. The advantage of this is that when you send result to report portal, then you will see defect severity as Parent

Go to images directory to see how report looks like on report portal
