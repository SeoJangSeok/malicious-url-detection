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
                    `API 요청 실패: ${response.status}`
                )
            }

            const data = await response.json();

            let message;
            let resultClass;

            switch (data.final_prediction) {
                case "NORMAL":
                    resultTitle = "정상";
                    message = "정상 URL로 판단되었습니다.";
                    resultClass = "safe";
                    break;

                case "MALICIOUS":
                    resultTitle = "악성";
                    message = "악성 URL로 판단되었습니다.";
                    resultClass = "malicious";
                    break;

                default:
                    message = "판정 결과를 확인할 수 없습니다."
                    resultClass = "unknown";
            }

            resultElement.className = resultClass;

            resultElement.textContent =
                `${resultTitle}`;

        } catch (error) {
            console.error(error);

            resultElement.textContent =
                "검사 중 오류가 발생했습니다.";
        }
    });