from datetime import datetime
import unittest

import pandas as pd

from siem_mtad_gat import settings
from siem_mtad_gat.time_manager import TimeManager


class TestConversions(unittest.TestCase):

    def test_str_to_timestamp(self):
        a,b="2024-07-01T00:03:26Z","01/07/2024 00:03:26"
        alt_format="%d/%m/%Y %H:%M:%S"
        ao=TimeManager.str_to_timestamp(a)
        bo=datetime.strptime(b, alt_format)
        self.assertEqual(bo,ao)
        self.assertIsInstance(ao,pd.Timestamp)
        with self.assertRaises(Exception):
           TimeManager.str_to_timestamp(b)
           
    def test_timestamp_to_str(self):
        a="2024-07-01T00:03:26Z"
        ao=TimeManager.str_to_timestamp(a)
        aoo=TimeManager.timestamp_to_str(pd.Timestamp(ao))
        self.assertEqual(a,aoo)
    
    def test_round(self):
        #this test implicitly TimeManager.get_granularity_in_seconds too
        time ="2024-07-01T00:03:26Z"
        prior =TimeManager.str_to_timestamp("2024-07-01T00:03:24Z")
        post =TimeManager.str_to_timestamp("2024-07-01T00:03:27Z")
        g="3s"
        self.assertEqual(TimeManager.round_unit_timestamp_prior(time,g),prior)
        self.assertEqual(TimeManager.round_unit_timestamp_post(time,g),post)
        prior =TimeManager.str_to_timestamp("2024-07-01T00:00:00Z")
        post =TimeManager.str_to_timestamp("2024-07-02T00:00:00Z")
        g="24hour"
        self.assertEqual(TimeManager.round_unit_timestamp_prior(time,g),prior)
        self.assertEqual(TimeManager.round_unit_timestamp_post(time,g),post)
        prior =TimeManager.str_to_timestamp("2024-07-01T00:02:00Z")
        post =TimeManager.str_to_timestamp("2024-07-01T00:04:00Z")
        g=2
        self.assertEqual(TimeManager.round_unit_timestamp_prior(time,g),prior)
        self.assertEqual(TimeManager.round_unit_timestamp_post(time,g),post)

    def test_mod(self):
        ta =TimeManager.str_to_timestamp("2024-07-01T00:03:26Z")
        tb =TimeManager.str_to_timestamp("2024-07-01T00:04:26Z")
        m=list(range(2,9))
        r=[0,0,0,0,0,4.,4.,0]
        for mo,ro in zip(m,r): 
            self.assertEqual(ro,TimeManager._mod_frequency_shift(shift=ta,time=tb,frequency=mo))

#detectors' parameters (window_size,granularity)

PARAMS={1:(10,"3s"), 2:(4,"2hour"), 3:(8,5), 4:(9,"7s")} #0.05 ,120,5


class TestIntervals(unittest.TestCase):
    

    def test_detection_interval(self):
        expected_output={1: 0.55, 2:600, 3:45}
        for key,out in expected_output.items():
            a=TimeManager.get_detection_interval(*PARAMS.get(key)) # type: ignore
            self.assertEqual(a,out)
            

    def test_batch_interval(self):
        bsz={2: [(1,0.6),(2,720),(3,50)], 11: [(1,1.05),(2,1800),(3,95)],103: [(1,5.65),(2,12840),(3,555)]} # batch_size: (id,batch_interval)
        for batch_size,outs in bsz.items():
            for z in outs:
                (idd,batch_interval)=z
                (window_size,granularity)=PARAMS.get(idd)
                o=TimeManager.get_batch_interval(batch_size,granularity,window_size)
                self.assertAlmostEqual(batch_interval,o)


    def test_historical(self):
        #requests historical runmode (start_time,end_time) #PARAMS={1:(10,"3s"), 2:(4,"2hour"), 3:(8,5), 4:(9,"7s")}
        r=("2024-07-01T00:03:24Z","2024-08-04T00:05:01Z")
        out={1:("2024-07-01T00:03:54Z","2024-08-04T00:05:03Z"),2:("2024-07-01T08:00:00Z","2024-08-04T02:00:00Z"),3:("2024-07-01T00:40:00Z","2024-08-04T00:10:00Z"), 4:("2024-07-01T00:04:23Z","2024-08-04T00:05:04Z")}
        fetch={1:("2024-07-01T00:03:24Z","2024-08-04T00:05:03Z"),2:("2024-07-01T00:00:00Z","2024-08-04T02:00:00Z"),3:("2024-07-01T00:00:00Z","2024-08-04T00:10:00Z"), 4:("2024-07-01T00:03:20Z","2024-08-04T00:05:04Z")}
        for k,v in fetch.items():
            window_size,granularity=PARAMS.get(k)
            f,o=TimeManager.get_intervals_historical(r[0],r[1],granularity=granularity,window_size=window_size,rounding=True)
            self.assertEqual(f,v)
            self.assertEqual(o,out.get(k))

    def test_batch(self):
        r="1993-07-01T00:05:09Z"
        end={1: "1993-07-01T00:05:09Z", 2:"1993-07-01T02:00:00Z",3:"1993-07-01T00:10:00Z", 4:"1993-07-01T00:05:15Z"} #PARAMS={1:(10,"3s"), 2:(4,"2hour"), 3:(8,5), 4:(9,"7s")}
        start_fetch={1: "1993-07-01T00:04:06Z", 2:"1993-06-29T20:00:00Z",3:"1993-06-30T22:35:00Z", 4:"1993-07-01T00:02:55Z"}
        start_out={1: "1993-07-01T00:04:36Z", 2:"1993-06-30T04:00:00Z",3:"1993-06-30T23:15:00Z", 4:"1993-07-01T00:03:58Z"}
        batch_size=11
        for iid,ti in end.items():
             (window_size,granularity)=PARAMS.get(iid)
             tostr=TimeManager.timestamp_to_str
             #no rounding
             self.assertEqual(r,tostr(TimeManager.get_end_time_fetch_timestamp_online(time=r,granularity=granularity,rounding=False)))
             #rounding
             self.assertEqual(ti,tostr(TimeManager.get_end_time_fetch_timestamp_online(time=r,granularity=granularity,rounding=True)))
             self.assertEqual(start_fetch.get(iid),TimeManager.get_start_time_fetch(run_mode=settings.RUN_MODE.BATCH,time=r,granularity=granularity,window_size=window_size,batch_size=batch_size))
             so,eo=TimeManager.get_output_interval_batch(time=r,granularity=granularity,batch_size=batch_size)
             self.assertEqual(eo,ti)
             self.assertEqual(start_out.get(iid),so)
  
    def test_realtime(self):
        r="1993-07-01T00:05:09Z"
        end={1: "1993-07-01T00:05:09Z", 2:"1993-07-01T02:00:00Z",3:"1993-07-01T00:10:00Z", 4:"1993-07-01T00:05:15Z"} #PARAMS={1:(10,"3s"), 2:(4,"2hour"), 3:(8,5), 4:(9,"7s")}
        start_fetch={1: "1993-07-01T00:04:36Z", 2:"1993-06-30T16:00:00Z",3:"1993-06-30T23:25:00Z", 4:"1993-07-01T00:04:05Z"}
        start_out={1: "1993-07-01T00:05:06Z", 2:"1993-07-01T00:00:00Z",3:"1993-07-01T00:05:00Z", 4:"1993-07-01T00:05:08Z"}
        for iid,ti in end.items():
             (window_size,granularity)=PARAMS.get(iid)
             tostr=TimeManager.timestamp_to_str
             #no rounding
             self.assertEqual(r,tostr(TimeManager.get_end_time_fetch_timestamp_online(time=r,granularity=granularity,rounding=False)))
             #rounding
             self.assertEqual(ti,tostr(TimeManager.get_end_time_fetch_timestamp_online(time=r,granularity=granularity,rounding=True)))
             self.assertEqual(start_fetch.get(iid),TimeManager.get_start_time_fetch(run_mode=settings.RUN_MODE.REALTIME,time=r,granularity=granularity,window_size=window_size))
             so,eo=TimeManager.get_output_interval_batch(time=r,granularity=granularity)
             self.assertEqual(eo,ti)
             self.assertEqual(start_out.get(iid),so)

