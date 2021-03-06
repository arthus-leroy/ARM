/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file                     : main.c
 * @brief                    : Main program body
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                                                opensource.org/licenses/BSD-3-Clause
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
# include <string.h>
# include <stdio.h>
# include <stdarg.h>

# include "Crypto/crypto_hash_sha256.h"
# include "Crypto/crypto_sign.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
# define SUINT32                sizeof(uint32_t)
# define DMA_BUFFER_SIZE        0x1000
# define PUBLIC_KEY_SIZE        crypto_sign_PUBLICKEYBYTES
# define PRIVATE_KEY_SIZE       crypto_sign_SECRETKEYBYTES
# define HASH_SIZE              crypto_hash_sha256_BYTES
# define SIGN_SIZE              crypto_sign_BYTES

# define PROGRAM_BASE           0x8040000    // sector 6 and 7
# define PROGRAM_SIZE_ADDRESS   (PROGRAM_BASE)
# define PROGRAM_SIGN_ADDRESS   (PROGRAM_SIZE_ADDRESS + SUINT32)
# define PROGRAM_FLASH          0x8040200
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
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
enum TX_ERR
{
    NO_ERR,
    ASSERT_ERR,
    DMA_ERROR,
    CORRUPT,
    WRONG_SIGN,
    INVALID_PROGRAM,
};

int dma_sent = 0;
void HAL_UART_TxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_sent = 1;
}

const unsigned char seed[32] = "abcdefghijklmnopqrstuvwxyz012345";
unsigned char public_key[PUBLIC_KEY_SIZE];
unsigned char private_key[PRIVATE_KEY_SIZE];

// LEN, OP, ERR, ARGS..., HASH
unsigned char tx[1024];

unsigned char dma1[DMA_BUFFER_SIZE];
unsigned char dma2[DMA_BUFFER_SIZE];

/// Current dma buffer
unsigned char *buff = dma2;
/// Previous dma buffer (received)
unsigned char *prev = NULL;

unsigned program_flash;

int dma_received = 0;
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_received = 1;
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
    tx[3 + tx[0]] = 0;    // won't bother with checksum, not really important

    HAL_UART_Transmit_DMA(&huart2, tx, 3 + tx[0] + 1);
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
    tx[3 + tx[0]] = 0;    // won't bother with checksum, not really important

    HAL_UART_Transmit_DMA(&huart2, tx, 3 + tx[0] + 1);

    while (dma_sent == 0)
        ;
}

void send_error(const int err)
{
    dma_sent = 0;

    tx[0] = 0;
    tx[1] = 0;
    tx[2] = err;
    tx[3 + tx[0]] = 0;    // won't bother with checksum, not really important

    HAL_UART_Transmit_DMA(&huart2, tx, 3 + tx[0] + 1);

    while (dma_sent == 0)
        ;
}

int process_dma_program(struct crypto_hash_sha256_state *hash, unsigned char *buff,
                        const unsigned size)
{
    if (buff)
    {
        crypto_hash_sha256_update(hash, buff, size);

        const uint32_t* b = (uint32_t*) buff;
        const unsigned s = size / SUINT32 + (size % SUINT32 != 0);
        for (int i = 0; i < s; i++)
            if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, program_flash + i * SUINT32, b[i]) != HAL_OK)
            {
                send_error(DMA_ERROR);
                return 1;
            }

        program_flash += size;
    }

    return 0;
}

int dma_timeout(unsigned ms)
{
    if (ms == 0)
        return 0;

    const uint32_t t = HAL_GetTick();
    while (dma_received == 0)
        if (HAL_GetTick() - t > ms)
        {
            HAL_UART_Abort(&huart2);
            send_error(DMA_ERROR);
            return 1;
        }

    return 0;
}

int receive_dma_program(struct crypto_hash_sha256_state *hash,
                         const int buff_size, const int process)
{
    dma_received = 0;

    if (HAL_UART_Receive_DMA(&huart2, buff, buff_size) != HAL_OK)
    {
        send_error(DMA_ERROR);
        return 1;
    }

    if (process)
        if (process_dma_program(hash, prev, DMA_BUFFER_SIZE))
            return 1;

    HAL_GPIO_TogglePin(LED_GPIO_Port, LED_Pin);

    // switch buffer
    prev = buff;
    buff = (buff == dma1 ? dma2 : dma1);

    // DMA finished while we were processing and it's a middle of message
    if (dma_received == 1)
    {
        send_error(DMA_ERROR);
        return 1;
    }

    if (dma_timeout(DMA_BUFFER_SIZE))
        return 1;

    return 0;
}

void assert(const char *code, const char *file, const int line, const int err)
{
    if (err)
    {
        tx[0] = sprintf((char*) tx + 3, "assertion \"%s\" failed: file \"%s\", line %d", code, file, line);
        tx[1] = 0;
        tx[2] = ASSERT_ERR;
        tx[3 + tx[0]] = 0;    // won't bother with checksum, not really important

        HAL_UART_Transmit_DMA(&huart2, tx, 3 + tx[0] + 1);

        while (1)
            ;
    }
}

unsigned char get_hex(unsigned char i, const int part)
{
    i = part ? i % 16 : i / 16;

    return i < 10 ? '0' + i : 'A' + i - 10;
}

void send_hex(const unsigned char *buff, const unsigned len)
{
    char b[2 * len + 1];
    for (unsigned i = 0; i < len; i++)
    {
        b[2 * i] = get_hex(buff[i], 0);
        b[2 * i + 1] = get_hex(buff[i], 1);
    }
    b[2 * len] = '\0';
    send_dma_blocking(NO_ERR, b);
}

int launch_program()
{
    const uint32_t size = *(volatile uint32_t*) PROGRAM_SIZE_ADDRESS;
    unsigned char *crypted_hash = (unsigned char*) PROGRAM_SIGN_ADDRESS;

    unsigned char hash[HASH_SIZE];
    crypto_hash_sha256(hash, (unsigned char*) PROGRAM_FLASH, size);

    // check the validity of the program in flash
    if (crypto_sign_verify_detached(crypted_hash, hash, HASH_SIZE, public_key))
        return 1;

    // Deactivate interruptions
//    __disable_irq();

    // Deinit peripherals
/*
    HAL_UART_DeInit(&huart2);
    __HAL_RCC_USART2_CLK_DISABLE();
    __HAL_RCC_USART2_FORCE_RESET();
    __HAL_RCC_USART2_RELEASE_RESET();
    __HAL_RCC_DMA1_CLK_DISABLE();

    HAL_GPIO_DeInit(LED_GPIO_Port, LED_Pin);
    __HAL_RCC_GPIOA_CLK_DISABLE();
*/

    // Set Interruption Table (VTOR)
    SCB->VTOR = (uint32_t) PROGRAM_FLASH;

    // Set reset handler (address is 5-8 bytes of the program)
    const volatile uint32_t pc = *(volatile uint32_t*) (PROGRAM_FLASH + 4);
    void (*program)(void) = (void (*)(void)) pc;

    // Set stack pointer (address is 1-4 bytes of the program)
    const volatile uint32_t sp = *(volatile uint32_t*) (PROGRAM_FLASH);

//    __HAL_SYSCFG_REMAPMEMORY_SYSTEMFLASH();

    __set_MSP(sp);

//    __disable_irq();
//    HAL_DeInit();
    // Jump on the program
    program();

    // Reinit handlers
    MX_GPIO_Init();
    MX_DMA_Init();
    MX_USART2_UART_Init();
    __enable_irq();

    return 0;
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
    crypto_sign_seed_keypair(public_key, private_key, seed);
    send_dma_blocking(NO_ERR, "Begin");
    HAL_Delay(500);
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
    while (1)
    {
        const int launch = HAL_GPIO_ReadPin(BUTTON_GPIO_Port, BUTTON_Pin);
        if (launch && launch_program())
            send_error(INVALID_PROGRAM);

        program_flash = PROGRAM_FLASH;

        HAL_FLASH_Unlock();

        // FLASH size : 16 (0), 16, 16, 16, 64, 128, 128, 128 (7)

        // Erase sector 6 and 7 (256 KB), should be enough
        FLASH_Erase_Sector(6, FLASH_VOLTAGE_RANGE_3);
        FLASH_Erase_Sector(7, FLASH_VOLTAGE_RANGE_3);
//        ASSERT( != HAL_OK)
        while (FLASH->SR & FLASH_SR_BSY)
            ;

        crypto_hash_sha256_state hash;
        crypto_hash_sha256_init(&hash);

        // STEP 1: Get size of the program
        uint32_t size;
        dma_received = 0;
        HAL_UART_Receive_DMA(&huart2, (unsigned char*) &size, SUINT32);
        while (dma_received == 0)
            ;

        const uint32_t total_size = size;

        // STEP 2: Receive and write the program
        // untreated data are always in prev
        int failed = 0;
        for (; size > DMA_BUFFER_SIZE; size -= DMA_BUFFER_SIZE)
            if (receive_dma_program(&hash, DMA_BUFFER_SIZE, 1))
            {
                failed = 1;
                break;
            }

        if (failed)
            continue;

        // receive last dma, but don't process anything
        // untreated data are in buff -> prev
        if (receive_dma_program(&hash, size, 0))
            continue;

        HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

        // STEP 3: Received encrypted hash
        dma_received = 0;
        unsigned char program_crypted_hash[SIGN_SIZE];
        HAL_UART_Receive_DMA(&huart2, program_crypted_hash, SIGN_SIZE);
        if (dma_timeout(SIGN_SIZE))
            continue;

        // STEP 4 : Receive integrity hash
        dma_received = 0;
        unsigned char program_hash[HASH_SIZE];
        HAL_UART_Receive_DMA(&huart2, program_hash, HASH_SIZE);
        if (dma_timeout(HASH_SIZE))
            continue;

        // process 2 last dmas (delayed process to not hinder the reception)
        process_dma_program(&hash, buff, DMA_BUFFER_SIZE);
        process_dma_program(&hash, prev, size);
        HAL_FLASH_Lock();

        unsigned char sha256_hash[HASH_SIZE];
        crypto_hash_sha256_final(&hash, sha256_hash);

        // compare integrity hash
        if (memcmp(sha256_hash, program_hash, HASH_SIZE))
        {
            send_error(CORRUPT);
            continue;
        }

        // decrypt program_crypted_hash with public key
        if (crypto_sign_verify_detached(program_crypted_hash, program_hash,
                                        crypto_sign_PUBLICKEYBYTES, public_key))
        {
            send_error(WRONG_SIGN);
            continue;
        }

        HAL_FLASH_Unlock();
        // write size
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, PROGRAM_SIZE_ADDRESS,
                          total_size);
        // write crypted hash
        for (unsigned i = 0; i < SIGN_SIZE / SUINT32; i++)
            HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, PROGRAM_SIGN_ADDRESS + i * SUINT32,
                              *(uint32_t*) (program_crypted_hash + i * SUINT32));
        HAL_FLASH_Lock();
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
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : BUTTON_Pin */
  GPIO_InitStruct.Pin = BUTTON_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BUTTON_GPIO_Port, &GPIO_InitStruct);

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
