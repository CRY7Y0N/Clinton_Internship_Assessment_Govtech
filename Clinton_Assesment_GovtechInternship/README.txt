Nginx Log Parser & User-Agent Enricher
Requirements
* Python 3.10 or higher

* Alternative, yet specifically: the user-agentspackage to enhance User-Agent identification.

* To produce an automated test: pytest( pip install pytest)

Project Files
   * main.py – the primary Python script that has the parser.

   * sample_access.log – the example Nginx access log file.

   * output.json – final output file (script has been executed)

   * instructions

   * tests/ – folder of automated test cases using pytest.

How to Run the Parser
Basic Run
python main.py -i sample_access.log -o output.json -pretty


With Summary
python main.py -i sample access.log -o output.json -pretty -summary


With Metadata Wrapper
python main.py -i sample_access.log -o output.json -pretty -wrap




After Manual Testing
Check the contents of the output.json file:
      * Techniques ( GET, POST, PUT ) are appropriate.

      * Status codes (200, 302, 404, etc.) correspond to the log.

      * User-Agent parses are able to categorize devices (PC, Mobile, Tablet, Bot) appropriately.

      * Run with the -summaryflag – ensure a list of unique IPs, browsers, OS, and status codes are displayed to the terminal.

      * Test corrupting a line (eg, delete quotes on a request) – ensure that the line is indicated with the mark of false "parse_ok": false.

      * Run with errors.log– confirm that a plain text error log has been written.

      * Run with strict– the program will exit with error code 2 when there are bad lines.



Automated Testing
The tests/ using folder pytest contains automated testing.
How to Run Tests
python -m pytest -q


What It Tests
The automated tests cover:
         * An authentic access log entry is read properly.

         * Lines that contain invalid syntax (regex mismatch, unclosed quotes, etc) are gracefully handled.

         * The detection of Windows 11 is as expected.

         * Android tablets are not mobiles, but tablets.

         * Multi-line end-to-end parsing is also correct.

         * Path requests containing spaces are still able to extract method, path, and protocol.

         * Bots (Googlebot, crawlers) can be classified as Bot.

         * Lines that are incorrectly formatted generate output during error handling.

         * The browsers, OS, devices and statuses are appropriately counted using summary statistics.




Sample Input
The sample_access.log has 10 real log entries which are mixed in a mixture of:
            * Mac, Android devices, Windows, iPhone and iPad.

            * Success (200), redirect (302), not found (404), server error (500)

            * Bots (Googlebot)

            * Various approaches to HTTP ( GET, POST, PUT).

Sample Output
Structured entries of the output.json are in the form of JSON. Each entry has:
               * Line number and parse status

               * IP address, original time (stamped) + ISO UTC (stamped)

               * method, path, protocol of HTTP request.

               * Status code and bytes sent

               * Referer and User-Agent

               * Parsed UA data: browser/family/version, operating system/family/version, device type.

Metadata is also produced when the program is executed with the option of --wrap:
                  * Source file

                  * Generation timestamp

                  * Processing duration

                  * Total lines processed

                  * Number of parse errors

                  * Which UA parser was used



Assumptions
                     * Nginx logs are in combined format.

                     * Windows 11 can also be displayed as Windows 10 unless Windows 11 is spelled out in the UA string.

                     * Android tablets that have the combination of Tablet and Mobile are considered as tablets.

                     * In case user-agentsthe library is not present, a simplistic heuristic is applied instead.