using System;
using System.Runtime.InteropServices;
using System.Text;

namespace pemicro
{
    public class Pemicro
    {

        #region Define enums

        /// <summary>
        /// List of all supported PEMicro port types.
        /// </summary>
        public enum PEMicroPortType
        {
            AUTODETECT = 99,
            PARALLEL_PORT_CABLE = 1,
            PCIBDM_LIGHTNING = 2,
            USB_MULTILINK = 3,
            CYCLONE_PRO_MAX_SERIAL = 4,
            CYCLONE_PRO_MAX_USB = 5,
            CYCLONE_PRO_MAX_ETHERNET = 6,
            OPENSDA_USB = 9,
        }

        /// <summary>
        /// Enumeration of all PEMicro Special features
        /// </summary>
        public enum PEMicroSpecialFeatures
        {
            /// Special Features for Power Management
            PE_PWR_SET_POWER_OPTIONS = 0x38000001,
            PE_PWR_TURN_POWER_ON = 0x38000011,
            PE_PWR_TURN_POWER_OFF = 0x38000012,

            /// Special Features for debug communications mode
            PE_ARM_SET_COMMUNICATIONS_MODE = 0x44000001,
            PE_ARM_SET_DEBUG_COMM_SWD = 0x00000000,
            PE_ARM_SET_DEBUG_COMM_JTAG = 0x00000001,

            PE_ARM_ENABLE_DEBUG_MODULE = 0x44000002,
            PE_ARM_WRITE_AP_REGISTER = 0x44000003,
            PE_ARM_READ_AP_REGISTER = 0x44000004,
            PE_ARM_WRITE_DP_REGISTER = 0x44000007,
            PE_ARM_READ_DP_REGISTER = 0x44000008,
            PE_ARM_FLUSH_ANY_QUEUED_DATA = 0x44000005,

            /// SWD control special features
            PE_ARM_GET_LAST_SWD_STATUS = 0x44000006,

            /// Special Features for Setting current device and core
            PE_GENERIC_GET_DEVICE_LIST = 0x58004000,
            PE_GENERIC_SELECT_DEVICE = 0x58004001,
            PE_GENERIC_GET_CORE_LIST = 0x58004002,
            PE_GENERIC_SELECT_CORE = 0x58004003,
            PE_SET_DEFAULT_APPLICATION_FILES_DIRECTORY = 0x58006000,

        }

        /// <summary>
        /// Enumeration of all possible SWD status values.
        /// </summary>
        public enum PEMicroSpecialFeaturesSwdStatus
        {
            PE_ARM_SWD_STATUS_ACK = 0x04,
            PE_ARM_SWD_STATUS_WAIT = 0x02,
            PE_ARM_SWD_STATUS_FAULT = 0x01,
        }

        /// <summary>
        /// Enumeration of all PEMicro Special features.
        /// </summary>
        public enum PEMicroMemoryAccessResults
        {
            /// No error occurred.
            PE_MAR_MEM_OK = 0,
            /// Access to memory was denied. (MCU is running).
            PE_MAR_MEM_NO_ACCESS = 1,
            /// A Bus error was detected.
            PE_MAR_MEM_BUS_ERROR = 2,
            /// Non-existent memory was accessed.
            PE_MAR_MEM_UNIMPLEMENTED = 3,
            /// Valid but indeterminate memory was accessed.
            PE_MAR_MEM_UNINITIALIZED = 4,
            /// Error occurred during programming sequence.
            PE_MAR_MEM_PROGRAMMING_ERROR = 5,
        }

        /// <summary>
        /// Memory access size used for block memory operations.
        /// </summary>
        public enum PEMicroMemoryAccessSize
        {
            PE_MEM_ACCESS_8BIT = 1,
            PE_MEM_ACCESS_16BIT = 2,
            PE_MEM_ACCESS_32BIT = 4,
        }

        /// <summary>
        /// List of Arm registers used for Writing/Reading operations.
        /// </summary>
        public enum PEMicroArmRegisters
        {
            /// Core registers
            PE_ARM_REG_R0 = 0,
            PE_ARM_REG_R1 = 1,
            PE_ARM_REG_R2 = 2,
            PE_ARM_REG_R3 = 3,
            PE_ARM_REG_R4 = 4,
            PE_ARM_REG_R5 = 5,
            PE_ARM_REG_R6 = 6,
            PE_ARM_REG_R7 = 7,
            PE_ARM_REG_R8 = 8,
            PE_ARM_REG_R9 = 9,
            PE_ARM_REG_R10 = 10,
            PE_ARM_REG_R11 = 11,
            PE_ARM_REG_R12 = 12,
            PE_ARM_REG_R13 = 13,
            PE_ARM_REG_R14 = 14,
            PE_ARM_REG_R15 = 15,
            PE_ARM_REG_SP = PE_ARM_REG_R13,
            PE_ARM_REG_LR = PE_ARM_REG_R14,
            PE_ARM_REG_PC = PE_ARM_REG_R15,

            /// Program status registers + Stack pointers
            PE_ARM_REG_XPSR = 16,
            /// Main SP
            PE_ARM_REG_MSP = 17,
            /// Process SP
            PE_ARM_REG_PSP = 18,

            /// Special registers
            /// CONTROL bits [31:24]
            /// FAULTMASK bits [23:16]
            /// BASEPRI bits [15:8]
            /// PRIMASK bits [7:0]
            PE_ARM_REG_SPECIAL_REG = 20,

            /// Floating-Point Status and Control Register
            PE_ARM_REG_FPSCR = 33,

            /// Floating point registers
            PE_ARM_REG_S0 = 64,
            PE_ARM_REG_S1 = 65,
            PE_ARM_REG_S2 = 66,
            PE_ARM_REG_S3 = 67,
            PE_ARM_REG_S4 = 68,
            PE_ARM_REG_S5 = 69,
            PE_ARM_REG_S6 = 70,
            PE_ARM_REG_S7 = 71,
            PE_ARM_REG_S8 = 72,
            PE_ARM_REG_S9 = 73,
            PE_ARM_REG_S10 = 74,
            PE_ARM_REG_S11 = 75,
            PE_ARM_REG_S12 = 76,
            PE_ARM_REG_S13 = 77,
            PE_ARM_REG_S14 = 78,
            PE_ARM_REG_S15 = 79,
            PE_ARM_REG_S16 = 80,
            PE_ARM_REG_S17 = 81,
            PE_ARM_REG_S18 = 82,
            PE_ARM_REG_S19 = 83,
            PE_ARM_REG_S20 = 84,
            PE_ARM_REG_S21 = 85,
            PE_ARM_REG_S22 = 86,
            PE_ARM_REG_S23 = 87,
            PE_ARM_REG_S24 = 88,
            PE_ARM_REG_S25 = 89,
            PE_ARM_REG_S26 = 90,
            PE_ARM_REG_S27 = 91,
            PE_ARM_REG_S28 = 92,
            PE_ARM_REG_S29 = 93,
            PE_ARM_REG_S30 = 94,
            PE_ARM_REG_S31 = 95,

            /// MDM-AP Status Register
            PE_ARM_REG_MDM_AP = 1000,

        }

        /// <summary>
        /// Target interfaces for the PEMicro.
        /// </summary>
        public enum PEMicroInterfaces
        {
            JTAG = 0,
            SWD = 1,
        }

        #endregion

        #region All functions in dll file
        /// dbkFCallWrapperAddr
        /// __dbk_fcall_wrapper
        /// TMethodImplementationIntercept
        /// external_pe_json_delete
        /// pe_export_pki_tree
        /// pe_import_pki_tree
        /// external_calculate_imx_64bit_passcode_based_on_key_and_challenge
        /// external_get_password_definition
        /// external_delete_password
        /// external_create_random_password
        /// external_list_passwords
        /// external_object_storage_destroy_storage_object
        /// external_object_storage_save_object_to_srec_file
        /// external_object_storage_relocate
        /// external_object_storage_set_start_address
        /// external_object_storage_get_start_address
        /// external_object_storage_crop_storage
        /// external_object_storage_delete_block
        /// external_object_storage_get_entire_range_including_gaps
        /// external_object_storage_get_range
        /// external_object_storage_get_number_of_ranges
        /// external_object_storage_get_block
        /// external_object_storage_put_block
        /// external_object_storage_load_data_from_object_file
        /// external_object_storage_create_storage_object
        /// external_pe_json_remove_subsection_from_list
        /// external_pe_json_add_subsection_description_to_list
        /// external_pe_json_get_subsection_name_from_description
        /// external_pe_json_get_subsection_descriptions_from_list
        /// external_validate_PJOFF_object
        /// external_pe_json_put_rawbuffer
        /// external_pe_json_get_rawbuffer
        /// external_pe_json_put_integer
        /// external_pe_json_put_string
        /// external_pe_json_get_integer
        /// external_pe_json_get_string
        /// external_pe_json_get_hexadecimal
        /// external_pe_json_free_json_file
        /// external_pe_generate_PJOFF_unique_id_from_filetype
        /// external_pe_save_PJOFF_to_file
        /// external_pe_save_PJOFF_to_string
        /// external_pe_load_PJOFF_from_file
        /// external_pe_load_PJOFF_from_string
        /// external_pe_create_PJOFF_object
        /// calculate_crc
        /// calculate_crc32
        /// aes128_generate_random_key_or_iv
        /// aes_decrypt_generic_raw
        /// aes_encrypt_generic_raw
        /// clr_brkpt
        /// set_inst_brkpt
        /// check_number_of_queued_exchanges
        /// get_exchange16_result
        /// process_all_queued_exchanges
        /// queue_data_exchange16
        /// writeDataBoot
        /// readDataBoot
        /// disconnectBootForRA
        /// connectBootForRA
        /// write_64bit_value
        /// read_64bit_value
        /// get_cable_version
        /// set_local_machine_ip_number
        /// 
        #endregion

        private const string DLLName = "unitacmp-64.dll";

        ///  char * version(void);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr version();

        public static String Version()
        {
            return Marshal.PtrToStringAnsi(version());
        }

        ///  unsigned short get_dll_version(void);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern ushort get_dll_version();

        public static UInt16 GetDllVersion()
        {
            return get_dll_version();
        }

        ///  unsigned int get_enumerated_number_of_ports(unsigned int PortType);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern uint get_enumerated_number_of_ports(uint PortType);

        public static UInt32 GetEnumeratedNumberOfPort(PEMicroPortType PortType) {
            return get_enumerated_number_of_ports((uint)PortType);
        }

        ///  char * get_port_descriptor_short(unsigned int PortType, unsigned int PortNum);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr get_port_descriptor_short(uint PortType, uint PortNum);

        public static String GetPortDescriptorShort(PEMicroPortType PortType, UInt32 PortNum)
        {
            return Marshal.PtrToStringAnsi(get_port_descriptor_short((uint)PortType, (uint)PortNum));
        }

        ///  char * get_port_descriptor(unsigned int PortType, unsigned int PortNum);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr get_port_descriptor(uint PortType, uint PortNum);

        public static String GetPortDescriptor(PEMicroPortType PortType, UInt32 PortNum)
        {
            return Marshal.PtrToStringAnsi(get_port_descriptor((uint)PortType, (uint)PortNum));
        }

        ///  bool pe_special_features(unsigned long featurenum,
        ///                          bool set_feature,
        ///                          unsigned long paramvalue1,
        ///                          unsigned long paramvalue2,
        ///                          unsigned long paramvalue3,
        ///                          void *paramreference1,
        ///                          void *paramreference2);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool pe_special_features(UInt32 featureNum, bool setFeature = true, UInt32 paramValue1 = 0, UInt32 paramValue2 = 0, UInt32 paramValue3 = 0, StringBuilder paramReference1 = null, StringBuilder paramReference2 = null);

        public static String GetDeviceList(String SearchText)
        {
            StringBuilder buffer = new StringBuilder(1000000); // Allocate buffer

            if (pe_special_features(
                featureNum: (UInt32)PEMicroSpecialFeatures.PE_GENERIC_GET_DEVICE_LIST,
                paramValue1: 1000000 - 1,
                paramReference1: buffer
                ))
            {
                return buffer.ToString();
            }
            else
            {
                return "";
            }
        }

        public static Boolean FlushData()
        {
            return pe_special_features((UInt32)PEMicroSpecialFeatures.PE_ARM_FLUSH_ANY_QUEUED_DATA);
        }

        public static Boolean SetApplicationFilesDirectory(String DirName)
        {
            return pe_special_features(
                featureNum: (UInt32)PEMicroSpecialFeatures.PE_SET_DEFAULT_APPLICATION_FILES_DIRECTORY,
                paramReference1: new StringBuilder(DirName)
            );
        }

        public static Boolean PowerOn()
        {
            return pe_special_features((UInt32)PEMicroSpecialFeatures.PE_PWR_TURN_POWER_ON);
        }

        public static Boolean PowerOff()
        {
            return pe_special_features((UInt32)PEMicroSpecialFeatures.PE_PWR_TURN_POWER_OFF);
        }

        public static Boolean SetInterface(PEMicroInterfaces Interface)
        {
            PEMicroSpecialFeatures If = PEMicroSpecialFeatures.PE_ARM_SET_DEBUG_COMM_JTAG;
            if (Interface == PEMicroInterfaces.SWD)
            {
                If = PEMicroSpecialFeatures.PE_ARM_SET_DEBUG_COMM_SWD;
            }
            return pe_special_features(
                 featureNum: (UInt32)PEMicroSpecialFeatures.PE_ARM_SET_COMMUNICATIONS_MODE,
                 paramValue1: (UInt32)If
            );
        }

        public static Boolean EnableDebugModule()
        {
            return pe_special_features(featureNum: (UInt32)PEMicroSpecialFeatures.PE_ARM_ENABLE_DEBUG_MODULE);
        }

        /// bool open_port_by_identifier(char * portName)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool open_port_by_identifier(StringBuilder portName);

        public static Boolean OpenPortByIdentifier(String PortName)
        {
            return open_port_by_identifier(new StringBuilder(PortName));
        }

        ///  void reset_hardware_interface(void);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void reset_hardware_interface();

        public static void ResetHardwareInterface()
        {
            reset_hardware_interface();
        }

        ///  unsigned char check_critical_error(void);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern byte check_critical_error();

        public static Byte CheckCriticalError()
        {
            return check_critical_error();
        }

        ///  void close_port(void);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void close_port();

        public static void ClosePort()
        {
            close_port();
        }

        ///  void open_debug_file(char *filename)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void open_debug_file(StringBuilder Filename);

        public static void OpenDebugFile(String Filename = "log_pemicro_comm.txt")
        {
            open_debug_file(new StringBuilder(Filename));
        }

        ///  void close_debug_file(char *filename)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void close_debug_file(StringBuilder Filename);

        public static void CloseDebugFile(String Filename = "log_pemicro_comm.txt")
        {
            close_debug_file(new StringBuilder(Filename));
        }

        ///  bool open_port(unsigned int PortType, unsigned int PortNum);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool open_port(uint PortType, uint PortNum);

        public static Boolean OpenPort(PEMicroPortType PortType, UInt32 PortNum)
        {
            return open_port((UInt32)PortType, PortNum);
        }

        ///  bool 
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool reenumerate_all_port_types();

        public static Boolean ReenumerateAllPortTypes()
        {
            return reenumerate_all_port_types();
        }

        ///  bool target_reset(void)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool target_reset();

        public static Boolean TargetReset()
        {
            return target_reset();
        }

        ///  bool target_check_if_halted(void)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool target_check_if_halted();

        public static Boolean TargetCheckIfHalted()
        {
            return target_check_if_halted();
        }

        ///  bool target_halt(void)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool target_halt();

        public static Boolean TargetHalt()
        {
            return target_halt();
        }

        ///  bool target_resume(void)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool target_resume();

        public static Boolean TargetResume()
        {
            return target_resume();
        }

        ///  bool target_step(void)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool target_step();

        public static Boolean TargetStep()
        {
            return target_step();
        }

        ///  bool get_mcu_register(unsigned long register_access_tags, unsigned long reg_num, unsigned long *reg_value)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool get_mcu_register(uint register_access_tags, uint reg_num, out uint reg_value);

        public static Boolean GetMCURegister(PEMicroArmRegisters Register, out UInt32 Value)
        {
            return get_mcu_register(0, (uint)Register, out Value);
        }

        ///  bool set_mcu_register(unsigned long register_access_tags, unsigned long reg_num, unsigned long reg_value)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool set_mcu_register(uint register_access_tags, uint reg_num, uint reg_value);

        public static Boolean SetMCURegister(PEMicroArmRegisters Register, UInt32 Value)
        {
            return set_mcu_register(0, (uint)Register, Value);
        }

        ///  bool load_bin_file(char *filename, unsigned int start_address)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool load_bin_file(StringBuilder Filename, uint StartAddress);

        public static Boolean LoadBinFile(String Filename, UInt32 StartAddress = 0)
        {
            return load_bin_file(new StringBuilder(Filename), StartAddress);
        }

        ///  bool load_srec_file(char *filename, unsigned int start_address)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool load_srec_file(StringBuilder Filename, uint StartAddress);

        public static Boolean LoadSrecFile(String Filename, UInt32 StartAddress = 0)
        {
            return load_srec_file(new StringBuilder(Filename), StartAddress);
        }

        ///  void set_debug_shift_frequency (signed long shift_speed_in_hz);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void set_debug_shift_frequency(int shift_speed_in_hz);

        public static void SetDebugShiftFrequency(Int32 ShiftSpeedInHz = 1000000)
        {
            set_debug_shift_frequency(ShiftSpeedInHz);
        }

        ///  void set_reset_pin_state(unsigned char state)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void set_reset_pin_state(byte state);

        public static void SetResetPinState(Boolean State)
        {
            set_reset_pin_state((byte)(State ? 1 : 0));
        }

        ///  void set_reset_delay_in_ms(unsigned int delaylength);
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void set_reset_delay_in_ms(uint delayLength);

        public static void SetResetDelayInMs(UInt32 delayLength)
        {
            set_reset_delay_in_ms(delayLength);
        }

        ///  unsigned char read_8bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                                mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern byte read_8bit_value(uint memory_access_tag, uint address, out uint mem_result);

        public static Byte Read8BitValue(UInt32 Address)
        {
            UInt32 result = 0;
            return read_8bit_value(0, Address, out result);
        }

        ///  void write_8bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                        unsigned long datum,
        ///                        mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void write_8bit_value(uint memory_access_tag, uint address, uint datum, out uint mem_result);

        public static void Write8BitValue(UInt32 Address, UInt32 Data)
        {
            UInt32 result = 0;
            write_8bit_value(0, Address, Data, out result);
        }

        ///  unsigned short read_16bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                                  mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern ushort read_16bit_value(uint memory_access_tag, uint address, out uint mem_result);

        public static UInt16 Read16BitValue(UInt32 Address)
        {
            UInt32 result = 0;
            return read_16bit_value(0, Address, out result);
        }

        ///  void write_16bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                         unsigned long datum,
        ///                         mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void write_16bit_value(uint memory_access_tag, uint address, uint datum, out uint mem_result);

        public static void Write16BitValue(UInt32 Address, UInt32 Data)
        {
            UInt32 result = 0;
            write_16bit_value(0, Address, Data, out result);
        }

        ///  unsigned long read_32bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                                 mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern uint read_32bit_value(uint memory_access_tag, uint address, out uint mem_result);

        public static UInt32 Read32BitValue(UInt32 Address)
        {
            UInt32 result = 0;
            return read_32bit_value(0, Address, out result);
        }

        ///  void write_32bit_value(unsigned long memory_access_tag, unsigned long address,
        ///                         unsigned long datum,
        ///                         mem_result *optional_mem_result)
        [DllImport(DLLName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern void write_32bit_value(uint memory_access_tag, uint address, uint datum, out uint mem_result);

        public static void Write32BitValue(UInt32 Address, UInt32 Data)
        {
            UInt32 result = 0;
            write_32bit_value(0, Address, Data, out result);
        }

        ///  bool get_block(unsigned int memory_access_tag,
        ///                 unsigned int address,
        ///                 unsigned int num_bytes,
        ///                 unsigned int access_sizing,
        ///                 unsigned char *buffer_ptr,
        ///                 unsigned char *optional_error_ptr)


        ///  bool put_block(unsigned int memory_access_tag,
        ///                 unsigned int address,
        ///                 unsigned int num_bytes,
        ///                 unsigned int access_sizing,
        ///                 unsigned char *buffer_ptr,
        ///                 unsigned char *optional_error_ptr)

    }
}
