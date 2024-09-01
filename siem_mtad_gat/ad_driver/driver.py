from siem_mtad_gat.ad_engine.mtad_gat.ad_engine import ADEngine
from siem_mtad_gat.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
import argparse
from siem_mtad_gat.ad_driver.driver_console import main as console_main
import siem_mtad_gat.settings as settings
import logging

logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), filemode='a', format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)

IC_LAUNCH_MSG = "IDPS-ESCAPE ADBox driver running in interactive console mode."
UC_LAUNCH_MSG = "IDPS-ESCAPE ADBox driver running use case scenario configuration"
CC_LAUNCH_MSG = "IDPS-ESCAPE ADBox checking connection with Wazuh/OpenSearch..."
DEF_LAUNCH_MSG = "IDPS-ESCAPE ADBox running in default mode"
TRAINING_RESPONSE = "Training response:"
PREDICTION_RESPONSE = "Prediction response:"
CONNECTION_ESTABLISHED_MSG = "Connection with Wazuh established successfully!"

# TO-REDESIGN (turn into a robust and extensible CLI: build on C5-DEC code base)

def print_and_log(m):
    print(m)
    logging.info(m)

def main():     
    # Initialize the argument parser
    parser = argparse.ArgumentParser(description='IDPS-ESCAPE ADBox, an open-source anomaly detection toolbox, developed in project CyFORT.')
    
    # Define the arguments
    parser.add_argument('-i', '--interactive', action='store_true', help='run the interactive console for training and prediction')
    parser.add_argument('-u', '--usecase', type=int, help='specify a configuration scenario/use case file for training and prediction')
    parser.add_argument('-c', '--connection', action='store_true', help='check connection with Wazuh')

    # Parse the arguments
    args = parser.parse_args()

    # Check connection with Wazuh
    if args.connection:
        print_and_log(CC_LAUNCH_MSG)
        try:
            wazuh_ingestor = WazuhDataIngestor()        
            if not wazuh_ingestor.check_connection():
                print(
                    "Could not establish a connection with Wazuh! verify ./siem_mtad_gat/assets/secrets/wazuh_credentials.json\n"
                    f"More details logged in {settings.LOGGING_FILE_NAME.format(name=__name__)}"
                )
                logging.error("Error connecting to Wazuh!") 
                logging.info("Fetching data from file. ")
            else:
                print_and_log(CONNECTION_ESTABLISHED_MSG)
        except Exception as e:
                print(f"Error occurred while getting SIEM alert data: {e}")
                logging.error(f"Error occurred while getting SIEM alert data: {e}")
        exit()

    # Handle the -i flag
    if args.interactive:
        print(IC_LAUNCH_MSG)
        logging.info(IC_LAUNCH_MSG)
        console_main()

    # Handle the -u flag taking an integer value as argument
    elif args.usecase is not None:
        print(UC_LAUNCH_MSG, f"uc_{args.usecase}.yaml.")
        logging.info(UC_LAUNCH_MSG, f"uc_{args.usecase}.yaml.")
        config_file = f"uc_{args.usecase}"
        engine = ADEngine()
        train_response = engine.train(default_config=False, custom_config_file=config_file, use_case_no=args.usecase)
        if train_response is not None: 
            print(TRAINING_RESPONSE, train_response)
            logging.info(TRAINING_RESPONSE, train_response)
        predict_response = engine.predict(predict_input_config=config_file, use_case_no=args.usecase)
        for res in predict_response:
            print(PREDICTION_RESPONSE, res)
            logging.info(PREDICTION_RESPONSE, res)
    
    # Default behavior if no arguments are provided
    else:
        print(DEF_LAUNCH_MSG)
        logging.info(DEF_LAUNCH_MSG)

        default_mode_confirmation = input("Are you sure you wish to run the default ADBox in default mode? (y/n): ").strip().lower()
    
        if default_mode_confirmation == 'y':
            engine = ADEngine() 
            train_response = engine.train()
            
            print_and_log(TRAINING_RESPONSE+train_response)

            predict_response = engine.predict()
            for res in predict_response:
                print_and_log(PREDICTION_RESPONSE+res)

        elif default_mode_confirmation == 'n':
            print("Exiting ADBox console... use adbox -h to see all CLI options.")
            exit()
        
if __name__ == "__main__": 
    main()
    