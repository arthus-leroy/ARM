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
# include <stdio.h>
# include <string.h>
# include <stdarg.h>

# include "Crypto/crypto_sign.h"
# include "Crypto/crypto_hash_sha256.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
# define RX_HEADER_SIZE			5	// size (4 bytes), op (1 byte)
# define TX_HEADER_SIZE			3	// size (1 byte), op (1 byte), error (1 byte)
# define MASTER_PASSWORD_SIZE 	32
# define PUBLIC_KEY_SIZE 		crypto_sign_PUBLICKEYBYTES
# define PRIVATE_KEY_SIZE 		crypto_sign_SECRETKEYBYTES
# define SIGN_SIZE 				crypto_sign_BYTES
# define HASH_SIZE 				crypto_hash_sha256_BYTES
# define DMA_BUFFER_SIZE 		1024
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
# define ASSERT(X) assert(#X, __FILE__, __LINE__, X)
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;
DMA_HandleTypeDef hdma_usart2_tx;
DMA_HandleTypeDef hdma_usart2_rx;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_DMA_Init(void);
static void MX_USART2_UART_Init(void);
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
    ADD_LOGIN,
    GET_LOGIN,
    DEL_LOGIN,
    QUIT,
};

enum TX_ERR
{
    NO_ERR,
	ASSERT_ERR,
	DMA_LATE,
    CORRUPT,
	WRONG_HASH,			// unused, for compatibility
    WRONG_PWD,
    LOGIN_NOT_EXISTS
};

const unsigned char seed[32] = "abcdefghijklmnopqrstuvwxyz012345";
unsigned char master_password[MASTER_PASSWORD_SIZE] = "abcdefghijklmnopqrstuvwxyz012345";
unsigned char public_key[PUBLIC_KEY_SIZE];
unsigned char private_key[PRIVATE_KEY_SIZE];
unsigned long long sign_len;

// FIXME: get the right pointer (a place or a way where ram won't get rewritten)
unsigned char *password_buffer = (unsigned char*) 0x20008000;

// LEN (1), OP (1), ERR (1), ARGS..., HASH
unsigned char tx[1024];
// LEN (4), OP (1), ARGS..., HASH
unsigned char rx[1024];

/// Checksum
unsigned checksum;

/// hash for SIGN operation
unsigned char hash[HASH_SIZE];

int dma_sent = 0;
void HAL_UART_TxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_sent = 1;
}

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

/*========== RX/TX functions ==========*/
unsigned get_rx_args_size(void)
{
    return *(unsigned*) rx;
}

unsigned char get_rx_op(void)
{
	return rx[4];
}

unsigned char *get_rx_args(void)
{
    return rx + RX_HEADER_SIZE;
}

unsigned char *get_tx_args(void)
{
	return tx + TX_HEADER_SIZE;
}

void set_tx_header(const unsigned char err)
{
    tx[0] = 0;      		// LEN
    tx[1] = get_rx_op();	// OP
    tx[2] = err;    		// ERR
}

void set_tx_error(const unsigned char err)
{
    tx[2] = err;
}

void set_tx_checksum(void)
{
    unsigned sum = 0;
    for (unsigned i = 0; i < tx[0]; i++)
        sum += tx[TX_HEADER_SIZE + i];

    tx[3 + tx[0]] = (unsigned char) (sum & 0xFF);
}

void send_dma(const int err, const char *format, ...)
{
	if (format)
	{
		va_list va;
		va_start(va, format);
		tx[0] = vsnprintf((char*) tx + 3, 1000, format, va);
		va_end(va);
	}
	else
		tx[0] = 0;

	tx[1] = 0;
	tx[2] = err;
	tx[TX_HEADER_SIZE + tx[0]] = 0;	// won't bother with checksum, not really important

	HAL_UART_Transmit_DMA(&huart2, tx, TX_HEADER_SIZE + tx[0] + 1);
}

void send_dma_blocking(const int err, const char *format, ...)
{
	if (format)
	{
		va_list va;
		va_start(va, format);
		tx[0] = vsnprintf((char*) tx + 3, 1000, format, va);
		va_end(va);
	}
	else
		tx[0] = 0;

	dma_sent = 0;

	tx[1] = 0;
	tx[2] = err;
	tx[TX_HEADER_SIZE + tx[0]] = 0;	// won't bother with checksum, not really important

	HAL_UART_Transmit_DMA(&huart2, tx, TX_HEADER_SIZE + tx[0] + 1);

	while (dma_sent == 0)
		;
}

void send_error(const int err)
{
	dma_sent = 0;

	tx[0] = 0;
	tx[1] = 0;
	tx[2] = err;
	tx[TX_HEADER_SIZE] = 0;	// won't bother with checksum, not really important

	HAL_UART_Transmit_DMA(&huart2, tx, TX_HEADER_SIZE + 1);

	while (dma_sent == 0)
		;
}

void assert(const char *code, const char *file, const unsigned line, const int res)
{
    if (res == 0)
    {
    	set_tx_header(ASSERT_ERR);
        tx[0] = sprintf((char*) tx + TX_HEADER_SIZE, "assertion \"%s\" failed: file \"%s\", line %d", code, file, line);
        set_tx_checksum();

        HAL_UART_Transmit_DMA(&huart2, tx, TX_HEADER_SIZE + tx[0] + 1);

        while (1)
        	;
    }
}

/*========== LOGIN functions ==========*/
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
int find_login(const unsigned char *login)
{
    // total size doesn't take its own size into account
    const unsigned total_size = (*(unsigned*) password_buffer) + sizeof(unsigned);

    int i = sizeof(unsigned);
    while (i < total_size)
    {
        const unsigned char login_size = *(password_buffer + i);
        i += sizeof(unsigned char);
        ASSERT(login_size != 0);

        const unsigned char pwd_size = *(password_buffer + i);
        i += sizeof(char) + sizeof(char);
        ASSERT(pwd_size != 0);

        const char *login_buff = (char*) password_buffer + i;
        if (strcmp(login_buff, (char*) login) == 0)
            return i;

        i += login_size + pwd_size;
    }

    return -1;
}

unsigned get_login_entry_size(const unsigned char *buff)
{
    const unsigned char login_size  = *(buff + 0);
    const unsigned char pwd_size    = *(buff + 1);

    return 2 + login_size + pwd_size;
}

void delete_login_at(const unsigned i)
{
	char *buff = (char*) password_buffer + i;

	const unsigned size = *(unsigned*) password_buffer;
	const unsigned entry_size = get_login_entry_size(password_buffer + i);

	// overwrite the login entry
	memcpy(buff, buff + entry_size, size - entry_size - i);
	// reduce the size
	*((unsigned*) password_buffer) -= entry_size;
}

int delete_login(const unsigned char *login)
{
    const unsigned i = find_login(login);
    if (i == -1)
        return 1;

    delete_login_at(i);

    return 0;
}

void add_login_at(const unsigned i, const char *creds)
{
    unsigned char *buff = password_buffer + i;

    unsigned char login_size    = strlen(creds);
    unsigned char pwd_size      = strlen(creds + login_size);

    *(buff + 0) = login_size;
    *(buff + 1) = pwd_size;
    memcpy(buff + 2, creds, login_size + pwd_size);
}

// creds = "login\0password\0"
void add_login(const unsigned char *creds)
{
	// delete login in case it already exists (overwrite login)
	delete_login(creds);

    const unsigned total_len = (*(unsigned*) password_buffer);
    const unsigned i = sizeof(unsigned) + total_len;

    add_login_at(i, (const char*) creds);
	const unsigned entry_size = get_login_entry_size(password_buffer + i);

	// increase the size
	*((unsigned*) password_buffer) += entry_size;
}

unsigned char *get_password(unsigned char *buff)
{
    return buff + 2 + *buff;    // 2 + login_size
}

unsigned get_password_len(const unsigned char *buff)
{
	return *(buff + 1);
}

/*========== DMA processing functions ==========*/
void process_dma_frame(struct crypto_hash_sha256_state *hash,
        			   const unsigned char *buffer, const int size)
{
    if (buffer)
    {
    	crypto_hash_sha256_update(hash, buffer, size);
    	for (int i = 0; i < size; i++)
    		checksum += buffer[i];
    	checksum &= 0xFF;
    }
}

int receive_dma_frame(struct crypto_hash_sha256_state *hash,
                      const int buff_size, const int process)
{
    dma_received = 0;

    if (HAL_UART_Receive_DMA(&huart2, buff, buff_size) != HAL_OK)
    	return 1;

    HAL_GPIO_TogglePin(LED_GPIO_Port, LED_Pin);
    if (process)
    	process_dma_frame(hash, prev, DMA_BUFFER_SIZE);

    // switch buffer
    prev = buff;
    buff = (buff == dma1 ? dma2 : dma1);

    if (dma_received == 1)
    {
        send_error(DMA_LATE);
        return 1;
    }

    while (dma_received == 0)
        ;

    return 0;
}

/*========== Global processing function ==========*/
const int use_password[] = { 0, 1, 0, 1, 1, 1, 0 };
int process_request(const int op)
{
    const unsigned char *args = get_rx_args();
    const unsigned arg_size = get_rx_args_size();

    int i;
    switch (op)
    {
        case NOP:
            return 0;

        case MOD_MAST_PWD:
            if (arg_size < MASTER_PASSWORD_SIZE)
                set_tx_error(CORRUPT);
            else
                memcpy(master_password, args, MASTER_PASSWORD_SIZE);
            break;

        case SEND_KEY:
        	memcpy(get_tx_args(), public_key, PUBLIC_KEY_SIZE);
        	tx[0] = PUBLIC_KEY_SIZE;
            break;

        case SIGN:
            crypto_sign_detached(tx + TX_HEADER_SIZE, &sign_len, hash, HASH_SIZE, private_key);
            tx[0] = sign_len;
            break;

        case ADD_LOGIN:
            add_login(args);
            break;

        case GET_LOGIN:
            if ((i = find_login(args)) == -1)
            {
                set_tx_error(LOGIN_NOT_EXISTS);
                break;
            }

            memcpy(get_tx_args(), get_password(password_buffer + i),
				   get_password_len(password_buffer + i));
            tx[0] = get_password_len(password_buffer + i);
            break;

        case DEL_LOGIN:
            if (delete_login(args))
                set_tx_error(LOGIN_NOT_EXISTS);
            break;

        case QUIT:
            return 0;

        default:
        	set_tx_error(CORRUPT);
    }

    return 1;
}

void send_hex(const unsigned char *buff, const unsigned len)
{
    char b[2 * len + 1];
    for (unsigned i = 0; i < len; i++)
    	sprintf(b + 2 * i, "%02X", buff[i]);
    send_dma_blocking(NO_ERR, b);
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
  MX_USART2_UART_Init();
  /* USER CODE BEGIN 2 */
    // generate key pair at the beginning
  	// as there is no RNG on the card, we must use a hardcoded seed
    crypto_sign_seed_keypair(public_key, private_key, seed);
    send_dma_blocking(NO_ERR, "Welcome to the manager !");
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
    while (1)
    {
    	HAL_Delay(100);
		HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

        struct crypto_hash_sha256_state state;
		crypto_hash_sha256_init(&state);

    	// STEP 1 : fetch header
        dma_received = 0;
        HAL_UART_Receive_DMA(&huart2, rx, RX_HEADER_SIZE);    // receive LEN and OP
        while (dma_received == 0)
            ;

        // beginning DMA reception
		HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_SET);

        unsigned len = get_rx_args_size();
        const unsigned total_len = len;
        const unsigned op = get_rx_op();

        checksum = 0;

        // STEP 2 : fetch master password (if needed)
        unsigned char master[MASTER_PASSWORD_SIZE];
        if (use_password[op])
        {
        	dma_received = 0;
        	HAL_UART_Receive_DMA(&huart2, master, MASTER_PASSWORD_SIZE);
        	while (dma_received == 0)
        		;
        }

        // STEP 3 : fetch arguments
        if (op == SIGN)
        {
    		int failed = 0;
        	// len can be greater than the rx buffer, so we drive it
        	// into separate buffers (dma1 and dma2)
        	for (; len > DMA_BUFFER_SIZE; len -= DMA_BUFFER_SIZE)
				if (receive_dma_frame(&state, DMA_BUFFER_SIZE, 1))
				{
					failed = 1;
					break;
				}

        	if (failed)
        		continue;

        	// receive last frame
			if (receive_dma_frame(&state, len, 0))
				continue;
        }
        else if (len)
        {
        	dma_received = 0;
        	HAL_UART_Receive_DMA(&huart2, rx + RX_HEADER_SIZE, len);
        	while (dma_received == 0)
        		;
        }

    	// STEP 4 : check rx integrity
    	unsigned char sum;
    	dma_received = 0;
    	HAL_UART_Receive_DMA(&huart2, &sum, sizeof(unsigned char));
    	while (dma_received == 0)
    		;

    	// ending DMA reception
		HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

        if (op == SIGN)
        {
			// process 2 last frame after receiving everything
        	if (total_len > DMA_BUFFER_SIZE)
        		process_dma_frame(&state, buff, DMA_BUFFER_SIZE);
        	process_dma_frame(&state, prev, len);

			crypto_hash_sha256_final(&state, hash);
        }
        else
        {
        	for (int i = 0; i < len; i++)
        		checksum += rx[RX_HEADER_SIZE + i];
        }

    	if (sum != (unsigned char) (checksum & 0xFF))
    	{
            send_error(CORRUPT);
            continue;
    	}

    	// STEP 5 : check master password if needed
        if (use_password[op])
        	if (memcmp(master, master_password, MASTER_PASSWORD_SIZE))
    		{
    			send_error(WRONG_PWD);
    			continue;
    		}

        // STEP 6 : dispatch operation
        set_tx_header(NO_ERR);
        if (process_request(op))
        {
            set_tx_checksum();

            dma_sent = 0;
            // send header (3 bytes) + args + checksum (1 byte)
            HAL_UART_Transmit_DMA(&huart2, tx, TX_HEADER_SIZE + tx[0] + 1);
            while (dma_sent == 0)
            	;
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
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
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
  __HAL_RCC_DMA1_CLK_ENABLE();

  /* DMA interrupt init */
  /* DMA1_Stream5_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Stream5_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Stream5_IRQn);
  /* DMA1_Stream6_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Stream6_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Stream6_IRQn);

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : LED_Pin */
  GPIO_InitStruct.Pin = LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LED_GPIO_Port, &GPIO_InitStruct);

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
