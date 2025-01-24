from datetime import date, datetime, timedelta
import logging
import pandas as pd
from siem_mtad_gat import settings
from siem_mtad_gat.commons import EscapeError, EscapeWarning



logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)


ERROR_GRANULARITY_FORMAT = "Unsupported granularity format. Specify the granularity (e.g, \"1min\", \"5min\", \"1s\", \"1hour\") if integer is interpreted as minutes."
RUNMODE_ERROR= "Runmode not valid, chose from "+str(settings.RUNMODE_LIST)
EXPECTED_FORMAT=settings.EXPECTED_STRING_TIME_FORMAT
BATCH_ERROR="Batch size is zero!"
EMPTY="Empty interval! Start time and end time should differ at least of a detection interval"

## Time unit's symbols 
HOURS='h'
SECONDS='s' #minimum granulary accepted
MINUTES='min'
DAY="day" #max granularity accepted


class TimeManager:
    """
    The TimeManager is the ADBox's component centralizing time management.
    Use TimeMager.get_expected_time_format() to print the expected time formats.
    """

    @staticmethod
    def str_to_timestamp(time:str) -> pd.Timestamp:
        """
        Convert string of the form EXPECTED_FORMAT to datetime timestamps.
        Use TimeMager.get_expected_time_format() to print the expected time formats.
        
        Args:
            time(str): time
        """
        t=datetime.strptime(time, settings.DATE_TIME_FORMAT)
        return pd.Timestamp(t)

    @staticmethod
    def timestamp_to_str(time:pd.Timestamp) -> str:
        """
        Convert timestamp to string of the form EXPECTED_FORMAT to datetime timestamps.

        Args:
            time(pd.Timestamp):  timestamp
        Returns:
            str: string in EXPECTED_FORMAT
        """
        time=time.round("1s") # round to the second to avoid error propagation
        return  time.strftime(settings.DATE_TIME_FORMAT)

    @staticmethod
    def round_unit_timestamp_prior(time:str,granularity:str) -> pd.Timestamp:
        """
        Round to prior unit timestamp

        Args:
            time(str): time in EXPECTED_FORMAT

        Returns:
            pd.Timestamp: rounded timestamp    
        """
        day=datetime.strptime(time, settings.DATE_TIME_FORMAT)
        t=pd.Timestamp(day)
        gins=str(TimeManager.get_granularity_in_seconds(granularity))
        return t.floor(gins+SECONDS)

    @staticmethod
    def round_unit_timestamp_post(time:str,granularity:str|int) -> pd.Timestamp:
        """
        Round to subsequent unit timestamp

        Args:
            time(str): time in EXPECTED_FORMAT
        Returns:
            pd.Timestamp: rounded timestamp  
        """
        day=datetime.strptime(time, settings.DATE_TIME_FORMAT)
        t=pd.Timestamp(day)
        gins=str(TimeManager.get_granularity_in_seconds(granularity))
        return t.ceil(gins+SECONDS)

    @staticmethod
    def get_granularity_str(granularity:str|int) -> str:
        """
        Convert  granularity (minutes) to string.

        Args:
            granularity (str or int): The granularity 
        Returns:
            int: The granularity as string.
        """
        if isinstance(granularity, int):
            return str(granularity)+MINUTES
        return granularity

    @staticmethod
    def get_granularity_in_minutes(granularity:str|int) -> int | float:
        """
        Convert granularity string to minutes.

        Args:
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.

        Returns:
            int: The granularity converted to minutes.

        Raises:
            ValueError: If granularity format is not supported.
        """
        # If granularity is already an integer (representing minutes), return it directly
        if isinstance(granularity, int):
            return granularity

        # Convert granularity to lowercase for case insensitivity
        granularity = granularity.lower()

        # Parse the numeric part of the granularity string into minutes
        if granularity.endswith(MINUTES):
                numeric_part = granularity[:-len(MINUTES)]
                if not numeric_part.isnumeric(): 
                    raise ValueError(ERROR_GRANULARITY_FORMAT)
                granularity_minutes = float(numeric_part)
        elif granularity.endswith(HOURS):
            numeric_part: str = granularity[:-len(HOURS)]
            if not numeric_part.isnumeric(): 
                raise ValueError(ERROR_GRANULARITY_FORMAT)
            granularity_minutes = float(numeric_part) * 60
        elif granularity.endswith(DAY):
            numeric_part = granularity[:-len(DAY)]
            if not numeric_part.isnumeric(): 
                raise ValueError(ERROR_GRANULARITY_FORMAT)
            granularity_minutes = float(numeric_part) * 1440
        elif granularity.endswith(SECONDS):
            numeric_part = granularity[:-len(SECONDS)]
            if not numeric_part.isnumeric(): 
                raise ValueError(ERROR_GRANULARITY_FORMAT)
            granularity_minutes: float = float(numeric_part) / 60.  # Convert seconds to minutes
        else:
            raise ValueError(ERROR_GRANULARITY_FORMAT)

        return granularity_minutes

    @staticmethod
    def get_granularity_in_seconds(granularity:str|int):
        """
        Convert granularity string to seconds.

        Args:
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.

        Returns:
            int: The granularity converted to seconds.

        Raises:
            ValueError: If granularity format is not supported.
        """
        # If granularity is in second returns it 
        if isinstance(granularity,str) and granularity.endswith(SECONDS):
            numeric_part = granularity[:-1]
            if not numeric_part.isnumeric(): 
                raise ValueError(ERROR_GRANULARITY_FORMAT)
            return float(numeric_part)
        else:
            return  TimeManager.get_granularity_in_minutes(granularity)*60
 

    @staticmethod
    def get_batch_interval(batch_size:int,granularity:str|int,window_size:int) -> int | float:
        """
        Calculate the batch interval in minutes based on batch size and granularity. 
        batch_interval=(window_size + batch_size)*granularity

        Args:
            batch_size (int): The size of each batch.
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.
            window_size (int): The window size.

        Returns:
            float: The calculated batch interval in minutes.

        Raises:
            ValueError: If batch_size is not a positive integer, or if granularity cannot be converted to an integer.
        """
        # Validate batch_size
        if not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("Batch size must be a positive integer.")
        
        # Get granularity in minutes using helper method
        granularity_minutes: int | float = TimeManager.get_granularity_in_minutes(granularity)

        # Calculate batch interval in minutes
        batch_interval_minutes: int | float = (window_size + batch_size) * granularity_minutes

        return batch_interval_minutes
    
    
    
    @staticmethod
    def get_detection_interval(window_size:int,granularity:str|int) -> int | float:
        """
        Calculates the detector interval in minutes based on the granularity and window size.
        detection_interval=(window_size + 1)*granularity

        Args:
            granularity (str): The granularity string, e.g., '1min'.
            window_size (int): The window size to multiply by.

        Returns:
            detection_interval (float): The resulting detector_interval in minutes. 
        
        Raises:
            ValueError: If the granularity format is unsupported.
        """  
        granularity_minutes: int | float = TimeManager.get_granularity_in_minutes(granularity)
        # Multiply by the window size and convert to float to calculate the detector interval 
        detector_interval: int | float  = granularity_minutes * (window_size + 1)


        return detector_interval

    @staticmethod
    def get_end_time_fetch_timestamp_online(granularity:int|str, time:str,rounding:bool=True) -> pd.Timestamp:
        """
        Calculates the fetching end time for online runmodes as a functions ofend time, batch size, and granularity,

        Args:
            granularity (str): The granularity string, e.g., '1min'.
            time (str): reference to compute the time, in the format expected format. 
            rounding (bool,optional): If True apply rounding. Default True.

        Returns:
            pd.Timestamp: The calculated fetch end time.

        Raises:
            ValueError: If granularity format is unsupported or if invalid run mode is provided.
        """ 
        #end_time(>)
        if rounding:
            return TimeManager.round_unit_timestamp_post(time=time,granularity=TimeManager.get_granularity_str(granularity)) 
        return TimeManager.str_to_timestamp(time)



    @staticmethod
    def get_start_time_fetch(run_mode, granularity:int|str, window_size:int, time:str, batch_size:int=0,rounding:bool=True) -> str:
        """
        Calculates the fetching start time based on the runmode, end time, batch size, and granularity.

        Args:
            run_mode (Enum): The detection run mode, which can be HISTORICAL, BATCH, or REALTIME.
            granularity (str): The granularity string, e.g., '1min'.
            time (str): reference to compute the time, in the format expected format. 
                    - For HISTORICAL should be requested start time.
                    - BATCH, REALTIME the request time
            window_size (int): The window size.
            batch_size (int, optional): The size of each batch.
            rounding (bool,optional): If True apply rounding. Default True.
            

        Returns:
            str: The calculated fetch start time.

        Raises:
            ValueError: If granularity format is unsupported or if invalid run mode is provided.
        """
        
        
        match run_mode: 
            case settings.RUN_MODE.HISTORICAL:
                #(<)star_time
                if rounding:
                    return TimeManager.timestamp_to_str(TimeManager.round_unit_timestamp_prior(time=time,granularity=TimeManager.get_granularity_str(granularity)))
                return time
            
            case settings.RUN_MODE.BATCH: #start time is always rounded for online
                
                if batch_size==0:
                    raise EscapeError(BATCH_ERROR,logger)
                #endtime(>)
                end_time_fetch: pd.Timestamp=TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=time,rounding=True)

                batch_interval=TimeManager.get_batch_interval(batch_size=batch_size,granularity=granularity,window_size=window_size)

                #start = end_time_fetch-batch_interval
                start_time_fetch= end_time_fetch - pd.Timedelta(batch_interval,unit="m")

                return TimeManager.timestamp_to_str(start_time_fetch)
 
            case settings.RUN_MODE.REALTIME:
                #endtime(>)
                end_time_fetch: pd.Timestamp=TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=time,rounding=True)
                    
                detection_interval=TimeManager.get_detection_interval(window_size=window_size,granularity=granularity)

                #start = end_time_fetch-detection_interval
                start_time_fetch= end_time_fetch - pd.Timedelta(detection_interval,unit="m")

                return TimeManager.timestamp_to_str(start_time_fetch)
 
            
        EscapeError(RUNMODE_ERROR,logger) 
        raise ValueError(RUNMODE_ERROR)


    @staticmethod
    def get_intervals_historical(request_start_time:str,request_end_time:str, granularity:int|str, window_size:int,rounding:bool=True) -> tuple[tuple[str, str], tuple[str, str]]:
        """
        Calculates output and fetching intervals extrema for hystorical runmode
        Args:

            request_start_time (str): input request start time
            request_end_time  (str): input request end time
            granularity (str): The granularity string, e.g., '1min'.
            window_size (int): The window size.
            rounding (int, optional): If rounding at fetching time.

        Returns:
           ((str,str),(str,str)): (start_time_fetch,end_time_fetch),(start_time_out,end_time_out)

        Raises:
            ValueError: If granularity format is unsupported or if invalid run mode is provided.
        """
        assert request_end_time>=request_start_time, "start time must be before end time!"
        
        #start fetch
        start_fetch=TimeManager.str_to_timestamp(TimeManager.get_start_time_fetch(run_mode=settings.RUN_MODE.HISTORICAL,time=request_start_time,granularity=granularity,window_size=window_size,rounding=rounding))
        start_fetch_rounded=TimeManager.str_to_timestamp(TimeManager.get_start_time_fetch(run_mode=settings.RUN_MODE.HISTORICAL,time=request_start_time,granularity=granularity,window_size=window_size,rounding=True))
        #start out
        granularity_minutes: int | float = TimeManager.get_granularity_in_minutes(granularity)
        # Multiply by the window size and convert to float to calculate the detector interval 
        ds: int | float  = granularity_minutes *window_size
        #output:(<)star_time+(window_size*granularity)
        start_time_out=start_fetch_rounded + pd.Timedelta(ds,unit="m")

        
        #compute frequency aka time unit in seconds
        freq=granularity_minutes*60.       
        #distance end request from rounded start
        delta:float=freq-TimeManager._mod_frequency_shift(time=TimeManager.str_to_timestamp(request_end_time),shift=start_fetch_rounded,frequency=freq)

        end_out=TimeManager.str_to_timestamp(request_end_time) + pd.Timedelta(delta,unit="s")
        end_fetch=end_out if rounding else TimeManager.str_to_timestamp(request_end_time)

        #to string
        fun=TimeManager.timestamp_to_str
        
        if start_fetch>=end_fetch: 
            raise EscapeWarning(EMPTY,logger)

        return  (fun(start_fetch),fun(end_fetch)), (fun(start_time_out),fun(end_out))
    
    
    @staticmethod
    def get_output_interval_batch(time, granularity:int|str,batch_size:int=1) -> tuple[str, str]:
        """
        Calculates output interval extrema for bac.
        Args:

            granularity (str): The granularity string, e.g., '1min'.
            window_size (int): The window size.
            batch_size (int, optional): The size of each batch.

        Returns:
            str: start_time_out
            str: end_time_out

        Raises:
            ValueError: If granularity format is unsupported or if invalid run mode is provided.
        """
        #endtime(>)
        end_time_out: pd.Timestamp=TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=time,rounding=True)
        #end_time_out- batch_size*granularity
        delta=batch_size*TimeManager.get_granularity_in_minutes(granularity)
        start_time_out= end_time_out- pd.Timedelta(delta,unit="m")
        return TimeManager.timestamp_to_str(start_time_out),TimeManager.timestamp_to_str(end_time_out)

    @staticmethod
    def get_today_str() -> str:
        """
        Returns the current date in the format expected date.


        Returns:
            str: Index date in 'YYYY-MM-DD' format.
        """        
        # Return today's date in 'YYYY-MM-DD' format
        return datetime.today().strftime(settings.DATE_FORMAT)
    

        
    @staticmethod
    def get_index_current_month() -> str:
        """
        Returns the index date in the format 'YYYY-MM-*' based on the current date.

        It returns the current month and year with date as '*'.

        Returns:
            str: Index date in 'YYYY-MM-*' format.
        """        
        # Return current month and year with '*'
        return  datetime.today().strftime("%Y-%m-*")
    

    @staticmethod
    def get_expected_time_format():
        """
        Prints the expected time formats
        """
        print(f"Timestap format: {settings.DATE_TIME_FORMAT}")
        print(f"Date format: {settings.DATE_FORMAT}")

    @staticmethod
    def now_str() -> str:
        """
        Returns:
            str: Returns the current timestanp in the format expected date.
        """        
        return datetime.now().strftime(settings.DATE_TIME_FORMAT)

    @staticmethod
    def _diff_timestamps_seconds(ta:pd.Timestamp,tb:pd.Timestamp) -> float:
        "Returns absolute distance between ta and tb in seconds"
        return (ta.value-tb.value)/pow(10,9) 
    
    @staticmethod
    def _mod_frequency_shift(time:pd.Timestamp,shift:pd.Timestamp,frequency:float) -> float:
        "modulo frequency shifted"
        return (TimeManager._diff_timestamps_seconds(time,shift))%frequency

    @staticmethod
    def batch_shift(batch_size,granularity):
        return batch_size*TimeManager.get_granularity_in_seconds(granularity)
        

    @staticmethod
    def next_batch_request(request:str,batch_shift:float):
        req_stamp: pd.Timestamp=TimeManager.str_to_timestamp(request)
        new= req_stamp + pd.Timedelta(batch_shift,unit="s")
        return TimeManager.timestamp_to_str(new)