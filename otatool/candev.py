from PCANBasic import *

class CanMsg:
    def __init__(self, id, data):
        self.id   = id
        self.data = data

class CanDev:
    def __init__(self, channel=1, bitrate=1000, isFd=False):
        self.m_pcan = None

        if channel != 1:
            print("invalid channel")
            return
        if bitrate != 500 and bitrate != 1000:
            print("invalid bitrate")
            return
        if isFd:
            print("fd not support")
            return

        try:
            self.m_pcan = PCANBasic()
        except:
            print("load PCANBasic.dll fail!")
            self.m_pcan = None
            return

        self.PcanHandle = TPCANHandle(0x50+channel)  # PCAN_USBBUS1 = TPCANHandle(0x51)
        self.IsFD       = False
        self.Bitrate    = PCAN_BAUD_1M if bitrate == 1000 else PCAN_BAUD_500K
        '''
        for normal CAN
          Bitrate=PCAN_BAUD_500K,
        for CAN FD, example: Nom: 1Mbit/s Data: 2Mbit/s
          Bitrate=b'f_clock_mhz=20, nom_brp=5, nom_tseg1=2, nom_tseg2=1, nom_sjw=1, data_brp=2, data_tseg1=3, data_tseg2=1, data_sjw=1') -> None:
        '''

    def Open(self):
        """
        Open CAN device
        """
        if not self.m_pcan:
            return False

        if self.IsFD:
            stsResult = self.m_pcan.InitializeFD(self.PcanHandle, self.Bitrate)
        else:
            stsResult = self.m_pcan.Initialize(self.PcanHandle, self.Bitrate)

        if stsResult != PCAN_ERROR_OK:
            print("Can not initialize. Please check the defines in the code.")
            self._ShowStatus(stsResult)
            return False
        return True

    def Close(self):
        """
        Close CAN device
        """
        if self.m_pcan:
            self.m_pcan.Uninitialize(PCAN_NONEBUS)

    def ReadMessage(self):
        """
        Read CAN message
        """
        ret = self.m_pcan.Read(self.PcanHandle)
        if ret[0] == PCAN_ERROR_OK:
            ok  = True
            msg = CanMsg(ret[1].ID, ret[1].DATA)
        else:
            ok  = (ret[0] == PCAN_ERROR_QRCVEMPTY)
            msg = None
        return ok, msg

    def WriteMessage(self, id, data, std=True):
        """
        Function for writing messages on CAN devices

        Returns:
            bool
        """
        msgCanMessage = TPCANMsg()
        msgCanMessage.ID      = id
        msgCanMessage.LEN     = len(data)
        msgCanMessage.MSGTYPE = PCAN_MESSAGE_STANDARD.value if std else PCAN_MESSAGE_EXTENDED.value
        for i in range(len(data)):
            msgCanMessage.DATA[i] = data[i]
        return self.m_pcan.Write(self.PcanHandle, msgCanMessage) == PCAN_ERROR_OK

    def StartTrace(self):
        """
        Activates tracing process
        """
        if not self._ConfigureTrace(traceFileSize=5):
            print("CAN ConfigureTrace fail")
            return False

        ## We activate the tracing by setting the parameter.
        stsResult = self.m_pcan.SetValue(self.PcanHandle, PCAN_TRACE_STATUS, PCAN_PARAMETER_ON)
        if stsResult != PCAN_ERROR_OK:
            self._ShowStatus(stsResult)
            return False
        return True

    def StopTrace(self):
        """
        Deactivates tracing process
        """
        ## We stop the tracing by setting the parameter.
        stsResult = self.m_pcan.SetValue(self.PcanHandle, PCAN_TRACE_STATUS, PCAN_PARAMETER_OFF)
        if stsResult != PCAN_ERROR_OK:
            self._ShowStatus(stsResult)

    def _ConfigureTrace(self, traceFilePath=b'', traceFileSize=2, overwrite=False, singleFile=True,
                       traceFileDate=True, traceFileTime=True, traceFileDataLength=False):
        """
        Configures the way how trace files are formatted.

        Args:
            traceFilePath: a fully-qualified and valid path to an existing directory
                           empty string to use the default path (calling process path)
            traceFileSize: the size (megabyte) of an tracefile, range between 1 and 100
            overwrite    : if existing tracefile overwrites when a new trace session is started
            singleFile   : if trace continue after reaching maximum size for the first file
            traceFileDate: if date will be add to filename
            traceFileTime: if time will be add to filename
            traceFileDataLength: if the column "Data Length" should be used instead of the column "Data Length Code"
        """
        stsResult = self.m_pcan.SetValue(self.PcanHandle, PCAN_TRACE_LOCATION, traceFilePath) ## Sets path to store files
        if stsResult == PCAN_ERROR_OK:

            stsResult = self.m_pcan.SetValue(self.PcanHandle, PCAN_TRACE_SIZE, traceFileSize) ## Sets the maximum size of file
            if (stsResult == PCAN_ERROR_OK):
                if (singleFile):
                    config = TRACE_FILE_SINGLE ## Creats one file
                else:
                    config = TRACE_FILE_SEGMENTED ## Creats more files

                ## Overwrites existing tracefile
                if overwrite:
                    config = config | TRACE_FILE_OVERWRITE

                ## Uses Data Length instead of Data Length Code
                if traceFileDataLength:
                    config = config | TRACE_FILE_DATA_LENGTH

                ## Adds date to tracefilename
                if traceFileDate:
                    config = config | TRACE_FILE_DATE

                 ## Adds time to tracefilename
                if traceFileTime:
                    config = config | TRACE_FILE_TIME

                stsResult = self.m_pcan.SetValue(self.PcanHandle,PCAN_TRACE_CONFIGURE, config)
                if (stsResult == PCAN_ERROR_OK):
                    return True

        self._ShowStatus(stsResult)
        return False

    def _GetFormattedError(self, error):
        """
        Help Function used to get an error as text

        Parameters:
            error = Error code to be translated

        Returns:
            A text with the translated error
        """
        ## Gets the text using the GetErrorText API function. If the function success, the translated error is returned.
        ## If it fails, a text describing the current error is returned.
        stsReturn = self.m_pcan.GetErrorText(error, 0x09)
        if stsReturn[0] != PCAN_ERROR_OK:
            return "An error occurred. Error-code's text ({0:X}h) couldn't be retrieved".format(error)
        else:
            message = str(stsReturn[1])
            return message.replace("'","",2).replace("b","",1)

    def _ShowStatus(self, status):
        """
        Shows formatted status

        Parameters:
            status = Will be formatted
        """
        print(self._GetFormattedError(status))
