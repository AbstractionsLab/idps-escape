import argparse
from adbox.ad_driver import *
from adbox.ad_engine.mtad_gat.ad_engine import ADEngine
from adbox.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
from adbox.ad_driver.driver_console import Console 
from adbox.commons import EscapeError, EscapeInfo, EscapeWarning
from adbox.shipper.wazuh_data_shipper import WazuhDataShipper


IC_LAUNCH_MSG = "IDPS-ESCAPE ADBox driver running in interactive console mode"
UC_LAUNCH_MSG = "IDPS-ESCAPE ADBox driver running use-case scenario configuration"
CC_LAUNCH_MSG = "IDPS-ESCAPE ADBox checking connection with Wazuh/OpenSearch..."
DEF_LAUNCH_MSG = "IDPS-ESCAPE ADBox running in default mode"
TRAINING_RESPONSE = "Training response:"
PREDICTION_RESPONSE = "Prediction response:"
CONNECTION_ESTABLISHED_MSG = "Connection with Wazuh established successfully!"
S_LAUNCH_MSG = "IDPS-ESCAPE ADBox shipping on"
s_EXIT_MSG= "Exit shipper installation. Check ADBox templates and policy correct installation from Wazuh Dashboard!"
# TO-REDESIGN (turn into a robust and extensible CLI: build on C5-DEC code base)
"""
def print_and_log(m):
    print(m)
    logging.info(m)
"""


def main():     
    # Initialize the argument parser
    parser = argparse.ArgumentParser(description='IDPS-ESCAPE ADBox, an open-source anomaly detection toolbox, developed in project CyFORT.')
    
    # Define the arguments
    parser.add_argument('-i', '--interactive', action='store_true', help='run the interactive console for training and prediction')
    parser.add_argument('-u', '--usecase', type=int, help='specify a configuration scenario/use-case file for training and prediction')
    parser.add_argument('-c', '--connection', action='store_true', help='check connection with Wazuh')
    parser.add_argument('-s', '--shipping', action='store_true', help='enable data shipping to Wazuh')

    # Parse the arguments
    args = parser.parse_args()

    # Handle the -s flag
    # check if template are installed
    if args.shipping:
        EscapeInfo(S_LAUNCH_MSG,logger)
        if args.usecase is None and  not args.interactive :
            wds=WazuhDataShipper(install=True)
            wds.add_rollover_policy()
            EscapeInfo(s_EXIT_MSG,logger)
            exit()
        else:
            wds=WazuhDataShipper(install=False)


    # Check connection with Wazuh
    if args.connection:
        EscapeInfo(CC_LAUNCH_MSG,logger)
        try:
            wazuh_ingestor = WazuhDataIngestor()        
            if not wazuh_ingestor.check_connection():
                EscapeInfo("Could not establish a connection with Wazuh! verify ./adbox/assets/secrets/wazuh_credentials.json",logger)
                raise EscapeWarning("Error connecting to Wazuh!") 
                #EscapeInfo("Fetching data from file. ")
            else:
                EscapeInfo(CONNECTION_ESTABLISHED_MSG,logger)
        except Exception as ex:
            raise EscapeWarning(f"Error occurred while getting SIEM alert data: {ex}",logger)
        exit()

    # Handle the -i flag
    if args.interactive:
        EscapeInfo(IC_LAUNCH_MSG,logger)
        console=Console(args.shipping)
        console.main()

    # Handle the -u flag taking an integer value as argument
    elif args.usecase is not None:
        EscapeInfo(UC_LAUNCH_MSG+f" uc_{args.usecase}.yaml.",logger)
        engine = ADEngine(ship_to_indexer=args.shipping)
        train_request=engine.get_training_requests_from_uc(uc_number=args.usecase)
        train_response = engine.training_pipeline(training_request=train_request)
        if train_response is not None:
            EscapeInfo(TRAINING_RESPONSE,logger)
            EscapeInfo(str(train_response),logger)
        pred_request=engine.get_prediction_requests_from_uc(uc_number=args.usecase)
        engine.run_prediction_pipeline(prediction_request=pred_request,uc_number=args.usecase)
        # Default behavior if no arguments are provided
        exit()
    else:
        EscapeInfo(DEF_LAUNCH_MSG,logger)

        default_mode_confirmation: str = input("Are you sure you wish to run the default ADBox in default mode? (y/n): ").strip().lower()
    
        if default_mode_confirmation == 'y':
            engine = ADEngine()

            train_request=engine.get_training_requests_from_uc()
            train_response = engine.training_pipeline(training_request=train_request)
            
            EscapeInfo(TRAINING_RESPONSE+str(train_response),logger)

        elif default_mode_confirmation == 'n':
            EscapeInfo("Exiting ADBox console... use adbox -h to see all CLI options.",logger)
            exit()
        
if __name__ == "__main__": 
    main()
    
    