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

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
# define PROGRAM_FLASH 0x8004000
# define DMA_BUFFER_SIZE 0x1000
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart1;
USART_HandleTypeDef husart2;
DMA_HandleTypeDef hdma_usart1_rx;
DMA_HandleTypeDef hdma_usart1_tx;

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
int sending;
void HAL_UART_TxCpltCallback(UART_HandleTypeDef *huart)
{
    sending = 0;
}

/// State of bootlader State Machine
unsigned char dma1[DMA_BUFFER_SIZE];
unsigned dma2[DMA_BUFFER_SIZE];

/// Current dma buffer
unsigned char *buff = dma2;
/// Previous dma buffer (received)
unsigned *prev = NULL;
int dma_received = 0;

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    dma_received = 1;
}

void process_dma_program(unsigned *buff,
                         cryto_hash_sha256_state *hash,
                         int size)
{
    if (buff)
    {
        crypto_hash_sha256_update(&hash, buff, size);
        for (int i = 0; i < size / sizeof(unsigned) + 1; i++)
            HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,
                              PROGRAM_FLASH + i * sizeof(unsigned),
                              prev[i]);
    }
}

void received_dma_program(cryto_hash_sha256_state *hash,
                          const int buff_size)
{
    dma_received = 0;

    HAL_UART_Receive_DMA(&huart1, buff, buff_size);
    process_dma_program(prev, buff_size, hash);

    while (dma_received == 0);

    // switch buffer
    prev = buff;
    buff = (buff == dma1 ? dma2 : dma1);
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

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
    while (1)
    {
        HAL_FLASH_Unlock();

        FLASH_MassErase(FLASH_VOLTAGE_RANGE_3, FLASH_BANK_1);
        while (FLASH->SR & FLASH_SR_BSY);
        // Check for error ?

        cryto_hash_sha256_state hash;
        crypto_hash_sha256_init(&hash);

        // Receive and write the program
        unsigned size;
        dma_received = 0;
        HAL_UART_Receive_DMA(&huart1, (unsigned char*) &size, sizeof(unsigned));
        while (dma_received == 0);

        for (; size >= DMA_BUFFER_SIZE; size -= DMA_BUFFER_SIZE)
            received_dma_program(&hash, DMA_BUFFER_SIZE);

        // receive last dma
        received_dma_program(&hash, size);
        // process last dma
        process_DMA_reception(prev, &hash, size);
        HAL_FLASH_Lock();

        dma_received = 0;
        unsigned char program_crypted_hash[crypto_hash_sha256_BYTES];
        HAL_UART_Receive_DMA(&huart1, program_crypted_hash, crypto_hash_sha256_BYTES);
        while (dma_received == 0);

        dma_received = 0;
        unsigned char program_hash[crypto_hash_sha256_BYTES];
        HAL_UART_Receive_DMA(&huart1, program_hash, crypto_hash_sha256_BYTES);
        while (dma_received == 0);

        // TODO: Check HASH
        unsigned char sha256_hash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256_final(&hash, sha256_hash);

        // compare hash
/*        if (strncmp(sha256_hash, program_hash, crypto_hash_sha256_BYTES))
        {
            printf("Corrupted message\n\r");
            continue;
        }*/

        // TODO: Check crypted HASH
        // decrypt program_crypted_hash with public key
        // FIXME

        // compare hash
/*        if (strncmp(sha256_hash, program_crypted_hash, crypto_hash_sha256_BYTES))
        {
            printf("\n\r");
            continue;
        }*/

        // Deactivate interruptions
        __disable_irq();

        // Deinit peripherals (TODO: forgot any ?)
        HAL_UART_DeInit(&huart1);
        HAL_USART_DeInit(&husart2);

        // Set Interruption Table (VTOR)
        SCB->VTOR = PROGRAM_FLASH;

        void (*program)(void);
        program = (void (*)(void)) PROGRAM_FLASH;

        // Set stack pointer
        __set_MSP(0);

        // Jump on the program
        program();

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