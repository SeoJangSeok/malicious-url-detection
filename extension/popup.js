let currentUrl = null;


// 현재 활성 탭의 URL 가져오기
chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    function (tabs) {
        const currentTab = tabs[0];

        currentUrl = currentTab.url;

        document.getElementById("current-url").textContent =
            currentUrl;
    }
);


// 검사 버튼 클릭
document
    .getElementById("check-button")
    .addEventListener("click", async function () {

        const resultElement =
            document.getElementById("result");

        // URL을 못 가져온 경우 요청하지 않음
        if (!currentUrl) {
            resultElement.textContent = "현재 페이지의 URL을 가져올 수 없습니다.";
            return ;
        }

        resultElement.textContent = "검사 중...";

        try {
            const response = await fetch(
                "http://127.0.0.1:8000/predict",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        url: currentUrl
                    })
                }
            );

            if (!response.ok) {
                throw new Error(
                    'API 요청 실패: ${response.status}'
                )
            }

            const data = await response.json();

            let message;
            let resultClass;

            switch (data.risk_level) {
                case "SAFE":
                    message = "정상으로 판단된 URL입니다.";
                    resultClass = "safe";
                    break;

                case "SUSPICIOUS":
                    message = "의심스러운 특징이 감지되었습니다.";
                    resultClass = "suspicious";
                    break;

                case "MALICIOUS":
                    message = "악성 URL일 가능성이 높습니다.";
                    resultClass = "malicious"
                    break;

                case "HIGH_RISK":
                    message = "매우 높은 위험이 감지되었습니다.";
                    resultClass = "high-risk"
                    break;

                default:
                    message = "판정 결과를 확인할 수 없습니다.";
                    resultClass = "unknown"
            }

            resultElement.className = resultClass;

            resultElement.textContent =
                `최종 위험도: ${data.risk_level}\n${message}`;

        } catch (error) {
            console.error(error);

            resultElement.textContent =
                "검사 중 오류가 발생했습니다.";
        }
    });