/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
# define MASTER_PASSWORD_SIZE 128
# define PUBLIC_KEY_SIZE crypto_box_PUBLICKEYBYTES
# define PRIVATE_KEY_SIZE crypto_box_SECRETKEYBYTES
# define SIGN_SIZE crypto_sign_BYTES
# define HASH_SIZE crypto_hash_sha256_BYTES
# define DMA_BUFFER_SIZE 1024
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
# define ASSERT(X) assert(#X, __FILE__, __LINE__, X)
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart1;
USART_HandleTypeDef husart2;
DMA_HandleTypeDef hdma_usart1_tx;
DMA_HandleTypeDef hdma_usart1_rx;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_DMA_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_USART2_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
enum OP
{
    NOP,
    MOD_MAST_PWD,
    SEND_KEY,
    SIGN,
    ADD_PWD,
    GET_PWD,
    DEL_PWD,
    QUIT,
};

enum TX_ERR
{
    NO_ERR,
    CORRUPT,
    WRONG_PWD,
    LOGIN_NOT_EXISTS
};

unsigned char master_password[MASTER_PASSWORD_SIZE];
unsigned char public_key[PUBLIC_KEY_SIZE];
unsigned char private_key[PRIVATE_KEY_SIZE];
unsigned long long sign_len;

// FIXME: get the right pointer (a place or a way where ram won't be rewritten)
unsigned char *password_buffer = 0x20008000;

// LEN, OP, ARGS..., HASH
unsigned char tx[1024];
// LEN, OP, ERR, ARGS..., HASH
unsigned char rx[1024];
/// Integrity Hash
unsigned char hash[HASH_SIZE];

void assert(const char *code, const char *file, const unsigned line, const int res)
{
    if (res == 0)
    {
        printf("\rassertion \"%s\" failed: file \"%s\", line %d\n", code, file, line);
        while (1);
    }
}

int sma_sent;
void HAL_UART_TxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_sent = 0;
}

/// State of bootlader State Machine
unsigned char dma1[DMA_BUFFER_SIZE];
unsigned char dma2[DMA_BUFFER_SIZE];

/// Current dma buffer
unsigned char *buff = dma2;
/// Previous dma buffer (received)
unsigned char *prev = NULL;
int dma_received = 0;

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_received = 1;
}

int get_rx_args_size(void)
{
    return rx[0];
}

unsigned char *get_rx_args(void)
{
    return rx + 2;
}

void set_tx_header(const unsigned char err)
{
    tx[0] = 0;      // LEN
    tx[1] = rx[1];  // OP
    tx[2] = err;    // ERR
}

void set_tx_error(const unsigned char err)
{
    tx[2] = err;
}

void add_tx_arg(const unsigned char arg)
{
    // tx[0] == len
    tx[tx[0]++] = arg;
}

void add_tx_args(const unsigned begin, unsigned char *buff, const unsigned size)
{
    for (unsigned i = 0; i < size; i++)
        add_tx_arg(buff[i]);
}

void add_tx_hash(void)
{
    // args begin at 3, after LEN, OP, ERROR
    crypto_hash_sha256(tx + tx[0] + 3, tx + 3, tx[0]);
}

/// Check integrity of message by summing the hash
int check_integrity(unsigned char val)
{
    unsigned sum = 0;
    for (unsigned i = 0; i < HASH_SIZE; i++)
        sum += hash[i];

    return val != (unsigned char) sum;
}

/**
 *     As we can't really use malloc, here is my data architecture attempt :
 *         total size (unsigned, 4 bytes)
 *
 *         login1 size (unsigned char, 1 byte)
 *         password1 size (unsigned char, 1 byte)
 *         login1 (char[], 1-255 bytes)
 *         password1 (char[], 1-255 bytes)
 *
 *         ...
 *
 *         loginN size (unsigned char, 1 byte)
 *         passwordN size (unsigned char, 1 byte)
 *         loginN (char[], 1-255 bytes)
 *         passwordN (char[], 1-255 bytes)
 */
int find_login(const char *login)
{
    // total size doesn't take its own size into account
    const unsigned total_size = (*(unsigned*) password_buffer) + sizeof(unsigned);

    int i = sizeof(unsigned);
    while (i < total_size)
    {
        const unsigned char login_size = *(password_buffer + i);
        i+= sizeof(unsigned char);
        ASSERT(login_size != 0);

        const unsigned char pwd_size = *(password_buffer + i);
        i += sizeof(char) + sizeof(char);
        ASSERT(pwd_size != 0);

        const char *login_buff = password_buffer + i;
        if (strcmp(login_buff, login) == 0)
            return i;

        i += login_size + pwd_size;
    }

    return -1;
}


unsigned get_login_entry_size(const unsigned char *buff)
{
    const unsigned char login_size     = *(buff + 0);
    const unsigned char pwd_size     = *(buff + 1);

    return (buff + 2) + login_size + pwd_size;
}

void delete_login_at(const unsigned i)
{
	unsigned buff = password_buffer + i;

    const unsigned char login_size 	= *(buff + 0);
    const unsigned char pwd_size 	= *(buff + 1);

    strcpy(buff, buff + get_login_entry_size(buff));
}

int delete_login(const char *login)
{
    const unsigned i = find_login(login);
    if (i == -1)
        return 1;

    delete_login_at(i);

    return 0;
}

// creds = "login\0password\0"
void add_login(const char *creds)
{
    delete_login(creds);

    unsigned *total_len = (unsigned*) password_buffer;

    unsigned char *buff = password_buffer + sizeof(unsigned) + *total_len;

    unsigned char login_size = strlen(creds);
    unsigned char pwd_size = strlen(creds + login_size);

    *(buff + 0) = login_size;
    *(buff + 1) = pwd_size;
    memcpy(buff + 2, creds, login_size + pwd_size);

    *total_len += 2 + login_size + pwd_size;
}

unsigned char *get_password(const unsigned char *buff)
{
    return buff + 2 + *buff;    // 2 + login_size
}

unsigned get_password_len(const unsigned char *buff)
{
	return *(buff + 1);
}

const int use_password[] = { 0, 1, 0, 1, 1, 1, 1 };
int process_request(const int op)
{
    if (use_password[op]
        && (get_args_size() < MASTER_PASSWORD_SIZE
        || strncmp(get_args(), master_password, MASTER_PASSWORD_SIZE)))
    {
        set_tx_header(WRONG_PWD);
        return 1;
    }

    set_tx_header(NO_ERR);

    const unsigned char *args = get_rx_args();
    const unsigned arg_size = get_rx_args_size();

    int i;
    switch (op)
    {
        case NOP:
            return 0;

        case MOD_MAST_PWD:
            if (arg_size < 2 * MASTER_PASSWORD_SIZE)
                set_tx_error(CORRUPT);
            else
                memcpy(master_password, args + MASTER_PASSWORD_SIZE, MASTER_PASSWORD_SIZE);
            break;

        case SEND_KEY:
            add_tx_args(0, public_key, PUBLIC_KEY_SIZE);
            break;

        case SIGN:
            crypto_sign(tx + 3, &sign_len, hash, HASH_LEN, private_key);
            tx[0] += sign_len;
            break;

        case ADD_PWD:
            add_login(args);
            break;

        case GET_PWD:
            if ((i = find_login(args)) == -1)
            {
                set_tx_error(LOGIN_NOT_EXISTS);
                break;
            }

            add_tx_args(0,
            		    get_password(password_buffer + i),
						get_password_len(password_buffer + i));
            break;

        case DEL_PWD:
            if (delete_login(args))
                set_tx_error(LOGIN_NOT_EXISTS);
            break;

        case QUIT:
            return 0;

        default:
            ASSERT(!"What the hell are you doing here ?");
    }

    return 0;
}

void process_dma_frame(cryto_hash_sha256_state *hash, const int size)
{
    dma_received = 0;

    HAL_UART_Receive_DMA(&huart1, cur, size);
    if (prev)
        crypto_hash_sha256_update(hash, prev, DMA_BUFFER_SIZE);

    prev = cur;

    while (dma_received == 0)
        ;
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART1_UART_Init();
  MX_USART2_Init();
  /* USER CODE BEGIN 2 */
    // FIXME: generate key
    crypto_box_keypair(public_key, private_key);
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
    while (1)
    {
        // TODO: fetch header
        dma_received = 0;
        HAL_UART_Receive_DMA(&huart1, rx, 2);    // receive LEN and OP
        while (dma_received == 0)
            ;

        unsigned len = rx[0];

        // TODO: fetch body
        while (len > DMA_BUFFER_SIZE)    // OP == SIGN
            process_dma_frame(state, DMA_BUFFER_SIZE);

        if (len > 0)
            process_dma_frame(state, len);

        if (prev)
            crypto_hash_sha256_update(&hash, prev, len);

        const unsigned char op = rx[1];
        if (process_request(op))
        {
            add_tx_hash();
            HAl_UART_Transmit_DMA(&huart1, tx, tx[0]);
        }
        else if (op == QUIT)
            return 0;
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);
  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  husart2.Instance = USART2;
  husart2.Init.BaudRate = 115200;
  husart2.Init.WordLength = USART_WORDLENGTH_8B;
  husart2.Init.StopBits = USART_STOPBITS_1;
  husart2.Init.Parity = USART_PARITY_NONE;
  husart2.Init.Mode = USART_MODE_TX_RX;
  husart2.Init.CLKPolarity = USART_POLARITY_LOW;
  husart2.Init.CLKPhase = USART_PHASE_1EDGE;
  husart2.Init.CLKLastBit = USART_LASTBIT_DISABLE;
  if (HAL_USART_Init(&husart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * Enable DMA controller clock
  */
static void MX_DMA_Init(void)
{

  /* DMA controller clock enable */
  __HAL_RCC_DMA2_CLK_ENABLE();

  /* DMA interrupt init */
  /* DMA2_Stream2_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA2_Stream2_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA2_Stream2_IRQn);
  /* DMA2_Stream7_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA2_Stream7_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA2_Stream7_IRQn);

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();

}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
